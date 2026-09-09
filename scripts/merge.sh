#!/usr/bin/env bash

# Legacy Bromite / legacy Chromium subresource-filter input builder.
# Produces filter-list text intended for Bromite's ruleset_converter
# (--input_format=filter-list) and the legacy Bromite-style adblock engine.
#
# Deliberately does NOT try to support uBlock/AdGuard cosmetic, scriptlet,
# procedural, regex, CSP/header, or arbitrary modifier syntax.

set -Eeuo pipefail
IFS=$'\n\t'
LC_ALL=C
export LC_ALL

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_FILE="${SOURCE_FILE:-$ROOT_DIR/sources.txt}"
CUSTOM_FILE="${CUSTOM_FILE:-$ROOT_DIR/custom-rules.txt}"
OUTPUT_FILE="${OUTPUT_FILE:-$ROOT_DIR/filters.txt}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build}"
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
USER_AGENT="${USER_AGENT:-legacy-bromite-filter-builder/2.0}"
REQUIRE_ALL_SOURCES="${REQUIRE_ALL_SOURCES:-0}"

# Set to 1 to keep simple URL/path network rules. Set to 0 for domain-only.
KEEP_URL_RULES="${KEEP_URL_RULES:-1}"

# Optional validation using an installed Chromium ruleset_converter.
# When enabled, the generated filters.txt is fed to the converter as a final gate.
VALIDATE_WITH_RULESET_CONVERTER="${VALIDATE_WITH_RULESET_CONVERTER:-0}"
RULESET_CONVERTER="${RULESET_CONVERTER:-ruleset_converter}"

need() { command -v "$1" >/dev/null 2>&1 || { printf 'ERROR: missing required command: %s\n' "$1" >&2; exit 1; }; }
for c in awk cat curl grep head mkdir mktemp mv rm sed sort tr wc; do need "$c"; done

[[ -f "$SOURCE_FILE" ]] || { printf 'ERROR: missing source file: %s\n' "$SOURCE_FILE" >&2; exit 1; }
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
cleanup() { rm -f -- "$tmp_output"; }
trap cleanup EXIT

total_downloaded_bytes=0

download_source() {
    local id="$1" url="$2" output actual_size
    output="$RAW_DIR/$id.txt"
    printf 'Downloading: %s\n' "$url"
    if ! curl --fail --silent --show-error --location --compressed \
        --retry "$CURL_RETRIES" --retry-delay "$CURL_RETRY_DELAY" \
        --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_TIMEOUT" \
        --max-filesize "$MAX_SOURCE_BYTES" --user-agent "$USER_AGENT" \
        "$url" --output "$output"; then
        printf 'DOWNLOAD_FAILED\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f -- "$output"; return 1
    fi
    [[ -f "$output" ]] || { printf 'NO_OUTPUT\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"; return 1; }
    actual_size="$(wc -c < "$output" | tr -d '[:space:]')"
    if (( actual_size > MAX_SOURCE_BYTES )); then
        printf 'TOO_LARGE\t%s\t%s bytes\n' "$url" "$actual_size" >> "$DOWNLOAD_ERRORS"
        rm -f -- "$output"; return 1
    fi
    if (( total_downloaded_bytes + actual_size > MAX_TOTAL_SOURCE_BYTES )); then
        printf 'TOTAL_SIZE_LIMIT\t%s\t%s bytes\n' "$url" "$actual_size" >> "$DOWNLOAD_ERRORS"
        rm -f -- "$output"; return 1
    fi
    total_downloaded_bytes=$((total_downloaded_bytes + actual_size))
    [[ -s "$output" ]] || { printf 'EMPTY\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"; rm -f -- "$output"; return 1; }
    if head -c 4096 "$output" | tr '[:upper:]' '[:lower:]' | grep -Eq '<html|<!doctype html|<head|<body'; then
        printf 'HTML_ERROR_PAGE\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f -- "$output"; return 1
    fi
    printf '%s\n' "$url" > "$RAW_DIR/$id.url"
}

sanitize_file() {
    local input="$1" output="$2" source="$3"
    awk -v source="$source" -v rejected="$REJECTED" -v keep_url="$KEEP_URL_RULES" '
    function reject(reason, value) {
        gsub(/\t/, " ", value)
        printf "%s\t%s\t%s\n", source, reason, value >> rejected
    }
    function valid_domain(value, n, p, i, part) {
        if (value !~ /^[A-Za-z0-9.-]+$/ || value ~ /^\.|\.$|\.\./ || length(value) > 253) return 0
        n = split(value, p, ".")
        if (n < 2 || value ~ /^[0-9.]+$/) return 0
        for (i=1; i<=n; i++) {
            part=p[i]
            if (part == "" || part ~ /^-/ || part ~ /-$/ || part !~ /^[A-Za-z0-9-]+$/ || length(part)>63) return 0
        }
        return 1
    }
    function emit_network(line, exception, body, host, rest) {
        exception = 0; body = line
        if (body ~ /^@@/) { exception=1; sub(/^@@/, "", body) }

        # Safe, converter-friendly network forms deliberately supported:
        #   ||example.com^                  domain/network block
        #   ||example.com/path*^            simple URL/path block
        #   |https://example.com/path|       absolute URL anchor
        #   @@||example.com^                exception
        # We do not pass through options/modifiers.
        if (body ~ /\$/ || body ~ /##|#@#|#\?#|#\$#|#%#|#\^#|#@%\?#/) return 0
        if (body ~ /^\/.*\/$/) return 0
        if (body ~ /[<>\\\001-\010\013\014\016-\037\177]/) return 0
        if (body ~ /[\t ]/) return 0
        if (body ~ /^(file|data|javascript|about|chrome|chrome-extension):/) return 0

        if (body ~ /^\|\|/) {
            host=body; sub(/^\|\|/, "", host)
            # Host is the first /, ?, or #. For the legacy-safe subset we only
            # allow an ordinary DNS hostname, followed by an optional path.
            rest=""
            pos = match(host, /[\/?#^|]/)
            if (pos) {
                rest = substr(host, pos)
                host = substr(host, 1, pos-1)
            }
            # Handle separator ^ and end-anchor | after host/path.
            if (host !~ /^[A-Za-z0-9.-]+$/ || !valid_domain(host)) return 0
            if (rest == "" || rest == "^" || rest == "|" || keep_url == 0) {
                printf "%s||%s^\n", (exception ? "@@" : ""), tolower(host)
                return 1
            }
            # Keep simple path rules only; no rule options.
            if (rest !~ /^[\/?#][A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%*^|-]*$/) return 0
            if (rest !~ /[\^|*]/ && rest ~ /\^/) return 0
            printf "%s||%s%s\n", (exception ? "@@" : ""), tolower(host), rest
            return 1
        }

        # Absolute URL anchored rules are supported conservatively.
        if (body ~ /^\|https?:\/\//) {
            if (body !~ /^\|https?:\/\/[A-Za-z0-9.-]+([\/?#][A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%*^|-]*)?\|?$/) return 0
            printf "%s%s\n", (exception ? "@@" : ""), body
            return 1
        }
        return 0
    }
    {
        original=$0; sub(/\r$/, "", $0); sub(/^\357\273\277/, "", $0); line=$0
        gsub(/^[ \t]+|[ \t]+$/, "", line)
        if (line == "" || line ~ /^!/) next
        if (line ~ /^\[Adblock/) { reject("metadata", original); next }
        if (line ~ /##|#@#|#\?#|#\$#|#%#|#\^#|#@%\?#/) { reject("cosmetic-filter", original); next }
        if (line ~ /\+js\(|:has-text\(|:contains\(|:matches-css\(|:xpath\(|:style\(/) { reject("scriptlet-procedural", original); next }
        if (line ~ /\$/) { reject("unsupported-modifier", original); next }
        if (line ~ /^\/.*\/$/) { reject("regex-filter", original); next }
        if (line ~ /[^\041-\176\t ]/) { reject("non-ascii-character", original); next }

        # Hosts-file conversion. Ignore inline comments after the hostname.
        if (line ~ /^(0\.0\.0\.0|127\.0\.0\.1|::1)[ \t]+/) {
            n=split(line, f, /[ \t]+/)
            if (n>=2 && valid_domain(f[2])) { printf "||%s^\n", tolower(f[2]); next }
            reject("invalid-host-entry", original); next
        }

        if (emit_network(line)) next
        if (line ~ /^@@/) reject("unsupported-exception-rule", original)
        else reject("unsupported-network-rule", original)
    }
    ' "$input" > "$output"
}

source_number=0
configured_sources=0
successful_downloads=0
while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//$'\r'/}"
    line="${line#$'\xef\xbb\xbf'}"
    line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ ! "$line" =~ ^https://[^[:space:]]+$ ]]; then
        printf 'sources.txt\tinvalid-source-url\t%s\n' "$line" >> "$REJECTED"; continue
    fi
    (( configured_sources < MAX_SOURCES )) || { printf 'ERROR: maximum source count exceeded: %s\n' "$MAX_SOURCES" >&2; exit 1; }
    configured_sources=$((configured_sources+1)); source_number=$((source_number+1))
    if download_source "$source_number" "$line"; then successful_downloads=$((successful_downloads+1)); fi
done < "$SOURCE_FILE"

(( configured_sources > 0 )) || { printf 'ERROR: no HTTPS source URLs found in: %s\n' "$SOURCE_FILE" >&2; exit 1; }
download_error_count="$(wc -l < "$DOWNLOAD_ERRORS" | tr -d '[:space:]')"
if (( REQUIRE_ALL_SOURCES )) && (( download_error_count > 0 )); then
    printf 'ERROR: one or more sources failed; see %s\n' "$DOWNLOAD_ERRORS" >&2; exit 1
fi
(( download_error_count == 0 )) || printf 'WARNING: %s source(s) failed; continuing\n' "$download_error_count" >&2

for input in "$RAW_DIR"/*.txt; do
    [[ -f "$input" ]] || continue
    id="${input##*/}"; id="${id%.txt}"
    sanitize_file "$input" "$CLEAN_DIR/$id.txt" "$(cat -- "$RAW_DIR/$id.url")"
done
if [[ -s "$CUSTOM_FILE" ]]; then sanitize_file "$CUSTOM_FILE" "$CLEAN_DIR/custom.txt" "custom-rules.txt"; fi

for file in "$CLEAN_DIR"/*.txt; do [[ -f "$file" ]] && cat -- "$file" >> "$COMBINED"; done
sed 's/\r$//' "$COMBINED" | sed '/^[[:space:]]*$/d' | sort -u > "$SORTED"
rule_count="$(wc -l < "$SORTED" | tr -d '[:space:]')"
(( rule_count > 0 )) || { printf 'ERROR: zero compatible network rules produced\n' >&2; exit 1; }

for clean_file in "$CLEAN_DIR"/*.txt; do
    [[ -f "$clean_file" ]] || continue
    sid="${clean_file##*/}"; sid="${sid%.txt}"
    if [[ "$sid" == custom ]]; then sname=custom-rules.txt; else sname="$(cat -- "$RAW_DIR/$sid.url")"; fi
    printf '%s\t%s\n' "$sname" "$(wc -l < "$clean_file" | tr -d '[:space:]')" >> "$SOURCE_COUNTS"
done

{
    printf '! Legacy Bromite / legacy Chromium subresource-filter compatible input\n'
    printf '! Network filtering rules only; intended for ruleset_converter --input_format=filter-list\n'
    printf '! Supported: domain-anchored rules, simple URL/path rules, exceptions, hosts-file conversion\n'
    printf '! Removed: cosmetic, scriptlet, procedural, regex, and filter-option/modifier rules\n'
    printf '! Generated by legacy-bromite-filter-builder 2.0\n'
    cat -- "$SORTED"
} > "$tmp_output"

output_bytes="$(wc -c < "$tmp_output" | tr -d '[:space:]')"
(( output_bytes <= MAX_OUTPUT_BYTES )) || { printf 'ERROR: output is %s bytes; maximum is %s\n' "$output_bytes" "$MAX_OUTPUT_BYTES" >&2; exit 1; }

if (( VALIDATE_WITH_RULESET_CONVERTER )); then
    need "$RULESET_CONVERTER"
    validation_out="$BUILD_DIR/ruleset-validation.dat"
    "$RULESET_CONVERTER" --input_format=filter-list --output_format=unindexed-ruleset --input_files="$tmp_output" --output_file="$validation_out"
    [[ -s "$validation_out" ]] || { printf 'ERROR: ruleset_converter produced an empty output\n' >&2; exit 1; }
fi

mv -f -- "$tmp_output" "$OUTPUT_FILE"
rejected_count="$(awk 'NR>1 {c++} END {print c+0}' "$REJECTED")"
printf '\nBuild completed successfully\n'
printf 'Output:                 %s\n' "$OUTPUT_FILE"
printf 'Compatible rules:      %s\n' "$rule_count"
printf 'Output size:            %s bytes\n' "$output_bytes"
printf 'Configured sources:     %s\n' "$configured_sources"
printf 'Successful downloads:   %s\n' "$successful_downloads"
printf 'Failed sources:         %s\n' "$download_error_count"
printf 'Downloaded bytes:       %s\n' "$total_downloaded_bytes"
printf 'Rejected rules:         %s\n' "$rejected_count"
printf 'Rejected report:        %s\n' "$REJECTED"
printf 'Download report:        %s\n' "$DOWNLOAD_ERRORS"
printf 'Source counts:          %s\n' "$SOURCE_COUNTS"
