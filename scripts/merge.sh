#!/usr/bin/env bash

set -Eeuo pipefail

IFS=$'\n\t'
LC_ALL=C
export LC_ALL

ROOT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &&
        pwd
)"

SOURCE_FILE="${SOURCE_FILE:-"$ROOT_DIR/sources.txt"}"
CUSTOM_FILE="${CUSTOM_FILE:-"$ROOT_DIR/custom-rules.txt"}"
OUTPUT_FILE="${OUTPUT_FILE:-"$ROOT_DIR/filters.txt"}"

BUILD_DIR="${BUILD_DIR:-"$ROOT_DIR/build"}"
RAW_DIR="$BUILD_DIR/raw"
CLEAN_DIR="$BUILD_DIR/clean"

MAX_SOURCE_BYTES="${MAX_SOURCE_BYTES:-52428800}"
MAX_OUTPUT_BYTES="${MAX_OUTPUT_BYTES:-20971520}"
MAX_TOTAL_SOURCE_BYTES="${MAX_TOTAL_SOURCE_BYTES:-524288000}"
MAX_SOURCES="${MAX_SOURCES:-100}"

CURL_TIMEOUT="${CURL_TIMEOUT:-120}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-20}"
CURL_RETRIES="${CURL_RETRIES:-4}"
CURL_RETRY_DELAY="${CURL_RETRY_DELAY:-3}"

USER_AGENT="${USER_AGENT:-strict-abp-adguard-filter-extractor/1.0}"
REQUIRE_ALL_SOURCES="${REQUIRE_ALL_SOURCES:-0}"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 ||
        die "missing required command: $1"
}

for command in \
    awk \
    cat \
    curl \
    grep \
    head \
    mkdir \
    mktemp \
    mv \
    rm \
    sed \
    sort \
    tr \
    wc; do
    need "$command"
done

[[ -f "$SOURCE_FILE" ]] ||
    die "missing source file: $SOURCE_FILE"

mkdir -p -- "$(dirname -- "$OUTPUT_FILE")"

rm -rf -- "$BUILD_DIR"
mkdir -p -- "$RAW_DIR" "$CLEAN_DIR"

REJECTED="$BUILD_DIR/rejected.txt"
DOWNLOAD_ERRORS="$BUILD_DIR/download-errors.txt"
COMBINED="$BUILD_DIR/combined.txt"
SORTED="$BUILD_DIR/sorted.txt"
SOURCE_COUNTS="$BUILD_DIR/source-counts.txt"

printf '# source\treason\trule\n' > "$REJECTED"
: > "$DOWNLOAD_ERRORS"
: > "$COMBINED"
: > "$SOURCE_COUNTS"

tmp_output="$(mktemp "${OUTPUT_FILE}.tmp.XXXXXX")"

cleanup() {
    rm -f -- "$tmp_output"
}

trap cleanup EXIT

total_downloaded_bytes=0

download_source() {
    local id="$1"
    local url="$2"
    local output="$RAW_DIR/$id.txt"
    local actual_size

    printf 'Downloading: %s\n' "$url"

    if ! curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --compressed \
        --retry "$CURL_RETRIES" \
        --retry-delay "$CURL_RETRY_DELAY" \
        --connect-timeout "$CURL_CONNECT_TIMEOUT" \
        --max-time "$CURL_TIMEOUT" \
        --max-filesize "$MAX_SOURCE_BYTES" \
        --user-agent "$USER_AGENT" \
        "$url" \
        --output "$output"; then

        printf 'DOWNLOAD_FAILED\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f -- "$output"
        return 1
    fi

    [[ -f "$output" ]] ||
        {
            printf 'NO_OUTPUT\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"
            return 1
        }

    actual_size="$(
        wc -c < "$output" |
            tr -d '[:space:]'
    )"

    if (( actual_size > MAX_SOURCE_BYTES )); then
        printf 'TOO_LARGE\t%s\t%s bytes\n' \
            "$url" \
            "$actual_size" >> "$DOWNLOAD_ERRORS"

        rm -f -- "$output"
        return 1
    fi

    if (( total_downloaded_bytes + actual_size > MAX_TOTAL_SOURCE_BYTES )); then
        printf 'TOTAL_SIZE_LIMIT\t%s\t%s bytes\n' \
            "$url" \
            "$actual_size" >> "$DOWNLOAD_ERRORS"

        rm -f -- "$output"
        return 1
    fi

    total_downloaded_bytes=$((total_downloaded_bytes + actual_size))

    if [[ ! -s "$output" ]]; then
        printf 'EMPTY\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f -- "$output"
        return 1
    fi

    # Reject common HTML error pages.
    if head -c 4096 "$output" |
        tr '[:upper:]' '[:lower:]' |
        grep -Eq '<html|<!doctype html|<head|<body'; then

        printf 'HTML_ERROR_PAGE\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f -- "$output"
        return 1
    fi

    printf '%s\n' "$url" > "$RAW_DIR/$id.url"

    return 0
}

sanitize_file() {
    local input="$1"
    local output="$2"
    local source="$3"

    awk \
        -v source="$source" \
        -v rejected="$REJECTED" '
    function reject(reason, value) {
        gsub(/\t/, " ", value)
        printf "%s\t%s\t%s\n", source, reason, value >> rejected
    }

    function valid_domain(value, count, parts, i, part) {
        if (value !~ /^[A-Za-z0-9.-]+$/)
            return 0

        if (value ~ /^\./)
            return 0

        if (value ~ /\.$/)
            return 0

        if (value ~ /\.\./)
            return 0

        if (length(value) > 253)
            return 0

        # Require a dotted hostname.
        count = split(value, parts, ".")
        if (count < 2)
            return 0

        # Reject IPv4 addresses.
        if (value ~ /^[0-9.]+$/)
            return 0

        for (i = 1; i <= count; i++) {
            part = parts[i]

            if (part == "")
                return 0

            if (part ~ /^-/ || part ~ /-$/)
                return 0

            if (part !~ /^[A-Za-z0-9-]+$/)
                return 0

            if (length(part) > 63)
                return 0
        }

        return 1
    }

    function print_strict_rule(value, exception, body, domain) {
        exception = 0
        body = value

        if (body ~ /^@@/) {
            exception = 1
            sub(/^@@/, "", body)
        }

        # Accepted grammar:
        #
        #   ||example.com^
        #   @@||example.com^
        #
        # Everything else is rejected.
        if (body !~ /^\|\|[A-Za-z0-9.-]+\^$/)
            return 0

        domain = body
        sub(/^\|\|/, "", domain)
        sub(/\^$/, "", domain)

        if (!valid_domain(domain))
            return 0

        if (exception)
            printf "@@||%s^\n", tolower(domain)
        else
            printf "||%s^\n", tolower(domain)

        return 1
    }

    {
        original = $0

        # Remove CR.
        sub(/\r$/, "", $0)

        # Remove UTF-8 BOM.
        sub(/^\357\273\277/, "", $0)

        line = $0

        # Trim leading and trailing spaces and tabs.
        gsub(/^[ \t]+|[ \t]+$/, "", line)

        if (line == "")
            next

        # ABP, AdGuard, EasyList, EasyPrivacy, and uBlock comments.
        if (line ~ /^!/)
            next

        # AdGuard metadata.
        if (line ~ /^\[Adblock/) {
            reject("metadata", original)
            next
        }

        # Cosmetic and CSS filters.
        if (line ~ /##|#@#|#\?#|#\$#|#%#|#\^#|#@%\?#/) {
            reject("cosmetic-or-css-filter", original)
            next
        }

        # Scriptlet and procedural filters.
        if (line ~ /\+js\(|:has-text\(|:contains\(|:matches-css\(|:xpath\(|:style\(/) {
            reject("scriptlet-or-procedural-filter", original)
            next
        }

        # All ABP, AdGuard, and uBlock modifiers are rejected.
        if (line ~ /\$/) {
            reject("filter-options-not-supported", original)
            next
        }

        # Regular-expression filters.
        if (line ~ /^\/.*\/$/) {
            reject("regular-expression-filter", original)
            next
        }

        # ASCII control characters.
        if (line ~ /[\001-\010\013\014\016-\037\177]/) {
            reject("control-character", original)
            next
        }

        # Keep output deterministic and ASCII-only.
        if (line ~ /[^\041-\176\t ]/) {
            reject("non-ascii-character", original)
            next
        }

        # Convert common hosts-file entries:
        #
        #   0.0.0.0 example.com
        #   127.0.0.1 example.com
        #   ::1 example.com
        #
        # Optional comments are allowed after the hostname.
        if (line ~ /^(0\.0\.0\.0|127\.0\.0\.1|::1)[ \t]+/) {
            count = split(line, fields, /[ \t]+/)

            if (count >= 2 &&
                fields[1] ~ /^(0\.0\.0\.0|127\.0\.0\.1|::1)$/ &&
                valid_domain(fields[2]) &&
                (count == 2 || fields[3] ~ /^#/)) {

                printf "||%s^\n", tolower(fields[2])
                next
            }

            reject("invalid-host-entry", original)
            next
        }

        # No whitespace is allowed in network rules.
        if (line ~ /[ \t]/) {
            reject("whitespace-not-allowed", original)
            next
        }

        # Reject unsafe or unsupported schemes.
        if (line ~ /^(file|data|javascript|about|chrome|chrome-extension):/) {
            reject("unsupported-scheme", original)
            next
        }

        # Reject characters that should never occur in this strict format.
        if (line ~ /[<>\\]/) {
            reject("unsafe-character", original)
            next
        }

        # Exception rule.
        if (line ~ /^@@/) {
            if (!print_strict_rule(line))
                reject("invalid-exception-rule", original)

            next
        }

        # Normal blocking rule.
        if (print_strict_rule(line))
            next

        reject("unsupported-abp-adguard-network-rule", original)
    }
    ' "$input" > "$output"
}

source_number=0
configured_sources=0
successful_downloads=0

while IFS= read -r line || [[ -n "$line" ]]; do
    # Remove CR and UTF-8 BOM.
    line="${line//$'\r'/}"
    line="${line#$'\xef\xbb\xbf'}"

    # Trim leading and trailing whitespace.
    line="$(
        printf '%s' "$line" |
            sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
    )"

    [[ -z "$line" ]] && continue

    # Comments in sources.txt.
    [[ "$line" == \#* ]] && continue

    # HTTPS-only source URLs.
    if [[ ! "$line" =~ ^https://[^[:space:]]+$ ]]; then
        printf '%s\tinvalid-source-url\t%s\n' \
            "sources.txt" \
            "$line" >> "$REJECTED"

        continue
    fi

    if (( configured_sources >= MAX_SOURCES )); then
        die "maximum source count exceeded: $MAX_SOURCES"
    fi

    configured_sources=$((configured_sources + 1))
    source_number=$((source_number + 1))

    if download_source "$source_number" "$line"; then
        successful_downloads=$((successful_downloads + 1))
    fi
done < "$SOURCE_FILE"

(( configured_sources > 0 )) ||
    die "no HTTPS source URLs found in: $SOURCE_FILE"

download_error_count="$(
    wc -l < "$DOWNLOAD_ERRORS" |
        tr -d '[:space:]'
)"

if (( REQUIRE_ALL_SOURCES )) && (( download_error_count > 0 )); then
    die "one or more sources failed; see: $DOWNLOAD_ERRORS"
fi

if (( download_error_count > 0 )); then
    printf \
        'WARNING: %s source(s) failed; continuing with available sources\n' \
        "$download_error_count" >&2
fi

# Sanitize downloaded sources.
for input in "$RAW_DIR"/*.txt; do
    [[ -f "$input" ]] || continue

    id="${input##*/}"
    id="${id%.txt}"

    source="$(cat -- "$RAW_DIR/$id.url")"

    sanitize_file \
        "$input" \
        "$CLEAN_DIR/$id.txt" \
        "$source"
done

# Sanitize optional custom rules.
if [[ -s "$CUSTOM_FILE" ]]; then
    sanitize_file \
        "$CUSTOM_FILE" \
        "$CLEAN_DIR/custom.txt" \
        "custom-rules.txt"
fi

# Combine all accepted rules.
for file in "$CLEAN_DIR"/*.txt; do
    [[ -f "$file" ]] || continue
    cat -- "$file" >> "$COMBINED"
done

# Normalize, remove blank lines, sort, and deduplicate.
sed 's/\r$//' "$COMBINED" |
    sed '/^[[:space:]]*$/d' |
    sort -u > "$SORTED"

rule_count="$(
    wc -l < "$SORTED" |
        tr -d '[:space:]'
)"

(( rule_count > 0 )) ||
    die "zero strict ABP/AdGuard rules produced"

# Record accepted-rule counts by source.
for clean_file in "$CLEAN_DIR"/*.txt; do
    [[ -f "$clean_file" ]] || continue

    source_id="${clean_file##*/}"
    source_id="${source_id%.txt}"

    if [[ "$source_id" == "custom" ]]; then
        source_name="custom-rules.txt"
    else
        source_name="$(cat -- "$RAW_DIR/$source_id.url")"
    fi

    source_rule_count="$(
        wc -l < "$clean_file" |
            tr -d '[:space:]'
    )"

    printf '%s\t%s\n' \
        "$source_name" \
        "$source_rule_count" >> "$SOURCE_COUNTS"
done

{
    printf '! Strict ABP/AdGuard network-rule subset\n'
    printf '! Compatible input sources: ABP, AdGuard, EasyList, EasyPrivacy, uBlock Origin\n'
    printf '! Accepted rules: ||domain^ and @@||domain^\n'
    printf '! Hosts entries converted to ||domain^\n'
    printf '! Modifiers, URL paths, wildcards, regex, cosmetic, scriptlet, and procedural rules removed\n'
    printf '! This is a strict extraction, not a complete syntax conversion\n'
    printf '! Generated by strict-abp-adguard-filter-extractor\n'
    cat -- "$SORTED"
} > "$tmp_output"

output_bytes="$(
    wc -c < "$tmp_output" |
        tr -d '[:space:]'
)"

if (( output_bytes > MAX_OUTPUT_BYTES )); then
    die "output is ${output_bytes} bytes; maximum is ${MAX_OUTPUT_BYTES} bytes"
fi

mv -f -- "$tmp_output" "$OUTPUT_FILE"

rejected_count="$(
    awk '
        NR > 1 {
            count++
        }

        END {
            print count + 0
        }
    ' "$REJECTED"
)"

printf '\n'
printf 'Build completed successfully\n'
printf 'Output:                 %s\n' "$OUTPUT_FILE"
printf 'Strict rules:           %s\n' "$rule_count"
printf 'Output size:            %s bytes\n' "$output_bytes"
printf 'Configured sources:     %s\n' "$configured_sources"
printf 'Successful downloads:   %s\n' "$successful_downloads"
printf 'Failed sources:         %s\n' "$download_error_count"
printf 'Downloaded bytes:       %s\n' "$total_downloaded_bytes"
printf 'Rejected rules:         %s\n' "$rejected_count"
printf 'Rejected report:        %s\n' "$REJECTED"
printf 'Download report:        %s\n' "$DOWNLOAD_ERRORS"
printf 'Source counts:          %s\n' "$SOURCE_COUNTS"
