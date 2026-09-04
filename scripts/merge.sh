#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

SOURCES_FILE="${SOURCES_FILE:-"$ROOT/sources.txt"}"
CUSTOM_FILE="${CUSTOM_FILE:-"$ROOT/custom-rules.txt"}"
OUT_FILE="${OUT_FILE:-"$ROOT/filters.txt"}"
BAD_FILE="${BAD_FILE:-"$ROOT/invalid-rules.txt"}"

MAX_SOURCE_BYTES="${MAX_SOURCE_BYTES:-52428800}"
CURL_TIMEOUT="${CURL_TIMEOUT:-120}"

TMP_DIR="$(mktemp -d)"
TMP_OUT="$TMP_DIR/filters.txt"
TMP_BAD="$TMP_DIR/invalid-rules.txt"
TMP_ERRORS="$TMP_DIR/download-errors.txt"

trap 'rm -rf "$TMP_DIR"' EXIT

log() {
    printf '[merge] %s\n' "$*" >&2
}

warn() {
    printf '[warn] %s\n' "$*" >&2
}

die() {
    printf '[error] %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 ||
        die "missing required command: $1"
}

for command in curl awk sed sort grep head tr wc sha256sum; do
    need "$command"
done

[[ -f "$SOURCES_FILE" ]] ||
    die "missing $SOURCES_FILE"

: > "$TMP_OUT"
: > "$TMP_BAD"
: > "$TMP_ERRORS"

trim() {
    local value="$1"

    value="${value//$'\r'/}"
    value="${value#$'\xef\xbb\xbf'}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    printf '%s' "$value"
}

is_source_comment_or_empty() {
    local line="$1"

    [[ -z "$line" ]] && return 0
    [[ "$line" == \#* ]] && return 0

    return 1
}

fetch_one() {
    local url="$1"
    local output="$2"

    if ! curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --compressed \
        --retry 4 \
        --retry-delay 3 \
        --connect-timeout 20 \
        --max-time "$CURL_TIMEOUT" \
        --max-filesize "$MAX_SOURCE_BYTES" \
        --user-agent "legacy-bromite-filter-builder/1.0" \
        "$url" \
        --output "$output"; then

        printf 'DOWNLOAD_FAILED\t%s\n' "$url" >> "$TMP_ERRORS"
        return 1
    fi

    if [[ ! -s "$output" ]]; then
        printf 'EMPTY_SOURCE\t%s\n' "$url" >> "$TMP_ERRORS"
        rm -f "$output"
        return 1
    fi

    # Reject common HTML error pages accidentally downloaded as filter lists.
    if head -c 4096 "$output" |
        tr '[:upper:]' '[:lower:]' |
        grep -Eq '<html|<!doctype|access denied|error 404|rate limit exceeded'; then

        printf 'HTML_ERROR_PAGE\t%s\n' "$url" >> "$TMP_ERRORS"
        rm -f "$output"
        return 1
    fi

    return 0
}

is_comment_or_empty() {
    local line="$1"

    [[ -z "$line" ]] && return 0
    [[ "$line" == '!'* ]] && return 0

    # Adblock metadata is not a filter rule.
    [[ "$line" == '[Adblock Plus '* ]] && return 0

    return 1
}

is_css_or_extended_rule() {
    local line="$1"

    [[ "$line" == *"##"* ]] ||
    [[ "$line" == *"#@#"* ]] ||
    [[ "$line" == *"#?#"* ]] ||
    [[ "$line" == *"#$#"* ]] ||
    [[ "$line" == *"#%#"* ]] ||
    [[ "$line" == *"#@%#"* ]] ||
    [[ "$line" == *"+js("* ]] ||
    [[ "$line" == *":has-text("* ]] ||
    [[ "$line" == *":contains("* ]] ||
    [[ "$line" == *":matches-css("* ]] ||
    [[ "$line" == *":xpath("* ]]
}

has_filter_option() {
    local line="$1"

    # Strict legacy mode: reject every option.
    #
    # This rejects:
    #   $script
    #   $third-party
    #   $domain=example.com
    #   $removeparam=x
    #   $redirect=...
    #   $important
    [[ "$line" == *'$'* ]]
}

has_invalid_characters() {
    local line="$1"

    # A valid rule must be a single line without whitespace.
    [[ "$line" =~ [[:space:]] ]] && return 0
    [[ "$line" =~ [[:cntrl:]] ]] && return 0

    return 1
}

valid_domain() {
    local domain="$1"

    [[ "$domain" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] ||
        return 1

    [[ "$domain" != *".."* ]] ||
        return 1

    [[ "$domain" != *".-"* ]] ||
        return 1

    [[ "$domain" != *"-."* ]] ||
        return 1

    return 0
}

convert_hosts_rule() {
    local line="$1"
    local ip domain extra

    read -r ip domain extra <<< "$line"

    [[ "$ip" == "0.0.0.0" ||
       "$ip" == "127.0.0.1" ||
       "$ip" == "::1" ]] || return 1

    [[ -n "$domain" && -z "$extra" ]] || return 1
    valid_domain "$domain" || return 1

    printf '||%s^\n' "$domain"
}

valid_domain_anchor_rule() {
    local line="$1"
    local exception=""

    if [[ "$line" == @@* ]]; then
        exception="@@"
        line="${line#@@}"
    fi

    [[ "$line" == \|\|* ]] || return 1
    line="${line#'||'}"

    # Extract the domain before the first separator/path/wildcard.
    local domain="${line%%[\^/*]*}"

    valid_domain "$domain" || return 1

    # A domain-anchor rule must have something after the domain:
    # ^, /path, or *.
    [[ "$line" != "$domain" ]] || return 1

    return 0
}

valid_url_rule() {
    local line="$1"

    [[ "$line" =~ ^https?://[^[:space:]]+$ ]] ||
    [[ "$line" =~ ^\|https?://[^[:space:]]+$ ]] ||
    [[ "$line" =~ ^@@https?://[^[:space:]]+$ ]] ||
    [[ "$line" =~ ^@@\|https?://[^[:space:]]+$ ]]
}

valid_plain_domain_rule() {
    local line="$1"

    valid_domain "$line"
}

valid_legacy_rule() {
    local line="$1"

    is_comment_or_empty "$line" && return 1
    is_css_or_extended_rule "$line" && return 1
    has_filter_option "$line" && return 1
    has_invalid_characters "$line" && return 1

    # Reject unsupported URL schemes.
    [[ "$line" =~ ^(file|data|javascript|about|chrome): ]] &&
        return 1

    # Reject regular-expression rules.
    [[ "$line" =~ ^/.*/$ ]] &&
        return 1

    # Reject metadata/directives.
    [[ "$line" == '['*']' ]] &&
        return 1

    # Allow domain-anchor blocking and exception rules.
    if [[ "$line" == \|\|* || "$line" == @@\|\|* ]]; then
        valid_domain_anchor_rule "$line"
        return $?
    fi

    # Allow full URL and URL-anchor rules.
    if valid_url_rule "$line"; then
        return 0
    fi

    # Convert simple domain rules to ||domain^.
    if valid_plain_domain_rule "$line"; then
        return 0
    fi

    return 1
}

record_invalid() {
    local source="$1"
    local reason="$2"
    local rule="$3"

    rule="${rule//$'\t'/ }"
    printf '%s\t%s\t%s\n' "$source" "$reason" "$rule" >> "$TMP_BAD"
}

process_file() {
    local file="$1"
    local source="$2"
    local line normalized converted

    while IFS= read -r line || [[ -n "$line" ]]; do
        normalized="$(trim "$line")"

        [[ -z "$normalized" ]] && continue

        # Comments are intentionally ignored, not written to output.
        is_comment_or_empty "$normalized" && continue

        # Convert hosts-file syntax.
        if converted="$(convert_hosts_rule "$normalized" 2>/dev/null)"; then
            printf '%s\n' "$converted" >> "$TMP_OUT"
            continue
        fi

        if is_css_or_extended_rule "$normalized"; then
            record_invalid "$source" "css-or-extended-rule" "$normalized"
            continue
        fi

        if has_filter_option "$normalized"; then
            record_invalid "$source" "filter-options-not-allowed" "$normalized"
            continue
        fi

        if has_invalid_characters "$normalized"; then
            record_invalid "$source" "whitespace-or-control-character" "$normalized"
            continue
        fi

        if [[ "$normalized" =~ ^/.*/$ ]]; then
            record_invalid "$source" "regular-expression-not-allowed" "$normalized"
            continue
        fi

        if valid_legacy_rule "$normalized"; then
            # Convert a simple hostname to a proper blocking rule.
            if valid_plain_domain_rule "$normalized"; then
                printf '||%s^\n' "$normalized" >> "$TMP_OUT"
            else
                printf '%s\n' "$normalized" >> "$TMP_OUT"
            fi
        else
            record_invalid "$source" "unknown-or-unsafe-syntax" "$normalized"
        fi
    done < "$file"
}

validate_sources_file() {
    local line

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="$(trim "$line")"

        is_source_comment_or_empty "$line" && continue

        [[ "$line" =~ ^https?://[^[:space:]]+$ ]] ||
            die "invalid source URL: $line"
    done < "$SOURCES_FILE"
}

main() {
    validate_sources_file

    local source_count=0
    local success_count=0
    local source local_name

    while IFS= read -r source || [[ -n "$source" ]]; do
        source="$(trim "$source")"

        is_source_comment_or_empty "$source" && continue

        source_count=$((source_count + 1))

        local_name="$TMP_DIR/$(printf '%s' "$source" | sha256sum | awk '{print $1}').txt"

        log "fetching $source"

        if fetch_one "$source" "$local_name"; then
            process_file "$local_name" "$source"
            success_count=$((success_count + 1))
        else
            warn "skipping failed source: $source"
        fi
    done < "$SOURCES_FILE"

    (( source_count > 0 )) ||
        die "sources.txt contains no sources"

    (( success_count > 0 )) ||
        die "all filter sources failed"

    if [[ -s "$CUSTOM_FILE" ]]; then
        log "processing custom-rules.txt"
        process_file "$CUSTOM_FILE" "custom-rules.txt"
    fi

    # Remove blank lines and duplicate rules.
    sed '/^[[:space:]]*$/d' "$TMP_OUT" |
        LC_ALL=C sort -u > "$TMP_DIR/sorted.txt"

    local rule_count
    rule_count="$(wc -l < "$TMP_DIR/sorted.txt" | tr -d ' ')"

    (( rule_count > 0 )) ||
        die "no compatible legacy Bromite rules were produced"

    {
        printf '! Legacy Bromite network filter list\n'
        printf '! CSS, scriptlets, regex, and filter options removed\n'
        printf '! Generated: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        cat "$TMP_DIR/sorted.txt"
    } > "$TMP_DIR/final.txt"

    # Atomic replacement: old filters.txt survives if the build fails.
    mv -f "$TMP_DIR/final.txt" "$OUT_FILE"
    mv -f "$TMP_BAD" "$BAD_FILE"

    local invalid_count
    invalid_count="$(wc -l < "$BAD_FILE" | tr -d ' ')"

    log "output: $OUT_FILE"
    log "compatible rules: $rule_count"
    log "rejected rules: $invalid_count"

    if [[ -s "$TMP_ERRORS" ]]; then
        warn "some sources failed:"
        cat "$TMP_ERRORS" >&2
    fi

    log "invalid rules: $BAD_FILE"
}

main "$@"
