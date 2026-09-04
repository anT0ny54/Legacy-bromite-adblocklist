#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

SOURCE_FILE="${SOURCE_FILE:-"$ROOT_DIR/sources.txt"}"
CUSTOM_FILE="${CUSTOM_FILE:-"$ROOT_DIR/custom-rules.txt"}"
OUTPUT_FILE="${OUTPUT_FILE:-"$ROOT_DIR/filters.txt"}"

BUILD_DIR="${BUILD_DIR:-"$ROOT_DIR/build"}"
RAW_DIR="$BUILD_DIR/raw"
CLEAN_DIR="$BUILD_DIR/clean"

MAX_SOURCE_BYTES="${MAX_SOURCE_BYTES:-52428800}"
CURL_TIMEOUT="${CURL_TIMEOUT:-120}"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 ||
        die "missing required command: $1"
}

for command in curl awk sed sort grep head tr wc mktemp; do
    need "$command"
done

[[ -f "$SOURCE_FILE" ]] ||
    die "missing source file: $SOURCE_FILE"

rm -rf "$BUILD_DIR"
mkdir -p "$RAW_DIR" "$CLEAN_DIR"

REJECTED="$BUILD_DIR/rejected.txt"
DOWNLOAD_ERRORS="$BUILD_DIR/download-errors.txt"

printf '# source\treason\trule\n' > "$REJECTED"
: > "$DOWNLOAD_ERRORS"

tmp_output="$(mktemp "${OUTPUT_FILE}.tmp.XXXXXX")"

cleanup() {
    rm -f "$tmp_output"
    rm -rf "$RAW_DIR" "$CLEAN_DIR"
}
trap cleanup EXIT

download_source() {
    local id="$1"
    local url="$2"
    local output="$RAW_DIR/$id.txt"

    printf 'Downloading: %s\n' "$url"

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
        --user-agent 'legacy-bromite-filter-builder/1.0' \
        "$url" \
        -o "$output"; then

        printf '%s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f "$output"
        return 1
    fi

    if [[ ! -s "$output" ]]; then
        printf 'EMPTY: %s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f "$output"
        return 1
    fi

    # Reject common HTML error pages.
    if head -c 4096 "$output" |
        tr '[:upper:]' '[:lower:]' |
        grep -Eq '<html|<!doctype|access denied|error 404|rate limit exceeded'; then

        printf 'HTML/ERROR: %s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f "$output"
        return 1
    fi

    return 0
}

# Strict legacy Bromite filter validation.
#
# Accepted:
#   ||example.com^
#   @@||example.com^
#   |https://example.com/ad.js
#   https://example.com/ad.js
#   /ads/banner
#   *advertising*
#
# Accepted host-file input:
#   0.0.0.0 example.com
#   127.0.0.1 example.com
#
# Rejected:
#   CSS filters
#   scriptlets
#   procedural filters
#   regular-expression filters
#   all $options
#   AdGuard/uBlock directives
#   malformed rules
sanitize_file() {
    local input="$1"
    local output="$2"
    local source="$3"

    awk -v source="$source" -v rejected="$REJECTED" -v build_dir="$BUILD_DIR" '
    function reject(reason, value) {
        gsub(/\t/, " ", value)
        printf "%s\t%s\t%s\n", source, reason, value >> rejected
        rejected_count++
    }

    function valid_domain(value) {
        return value ~ /^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$/ &&
               value !~ /(^|\.)(-|\.)/ &&
               value !~ /\.\./
    }

    {
        original = $0

        sub(/\r$/, "", $0)
        sub(/^\xef\xbb\xbf/, "", $0)

        line = $0
        gsub(/^[ \t]+|[ \t]+$/, "", line)

        if (line == "")
            next

        # ABP comments are allowed.
        if (line ~ /^!/)
            next

        # Reject metadata and non-network filter syntax.
        if (line ~ /^\[Adblock/) {
            reject("metadata", original)
            next
        }

        if (line ~ /^!#|##|#@#|#\?#|#\$#|#%#|#@%\?#/) {
            reject("css-or-directive", original)
            next
        }

        if (line ~ /\+js\(|:has-text\(|:contains\(|:matches-css\(|:xpath\(/) {
            reject("scriptlet-or-procedural", original)
            next
        }

        # Legacy mode intentionally rejects every option.
        if (line ~ /\$/) {
            reject("filter-options-not-allowed", original)
            next
        }

        # Regular-expression filters are excluded for maximum compatibility.
        if (line ~ /^\/.*\/$/) {
            reject("regular-expression", original)
            next
        }

        # No whitespace or control characters may remain in a rule.
        if (line ~ /[ \t]/) {
            # Convert hosts-file entries.
            count = split(line, fields, /[ \t]+/)

            if (count >= 2 &&
                fields[1] ~ /^(0\.0\.0\.0|127\.0\.0\.1|::1)$/ &&
                valid_domain(fields[2])) {
                print "||" fields[2] "^"
            } else {
                reject("whitespace-or-invalid-host-entry", original)
            }

            next
        }

        if (line ~ /[\001-\010\013\014\016-\037\177]/) {
            reject("control-character", original)
            next
        }

        # Reject unsupported URL schemes.
        if (line ~ /^(file|data|javascript|about|chrome):/) {
            reject("unsupported-scheme", original)
            next
        }

        # Domain-anchor filters.
        if (line ~ /^@@\|\|[A-Za-z0-9.-]+(\^|\/|\*)/) {
            print line
            next
        }

        if (line ~ /^\|\|[A-Za-z0-9.-]+(\^|\/|\*)/) {
            print line
            next
        }

        # URL-anchor filters.
        if (line ~ /^@@\|https?:\/\/[^|[:space:]]+$/) {
            print line
            next
        }

        if (line ~ /^\|https?:\/\/[^|[:space:]]+$/) {
            print line
            next
        }

        # Full URL filters.
        if (line ~ /^@@https?:\/\/[^[:space:]]+$/) {
            print line
            next
        }

        if (line ~ /^https?:\/\/[^[:space:]]+$/) {
            print line
            next
        }

        # Simple ABP substring filters.
        # Require at least one meaningful character and reject bare operators.
        if (line ~ /[A-Za-z0-9]/ &&
            line !~ /^[@|^*]+$/ &&
            line !~ /[<>]/) {
            print line
            next
        }

        reject("unknown-or-unsafe-syntax", original)
    }

    END {
        printf "%d\n", rejected_count + 0 > (build_dir "/rejected-count.txt")
    }
    ' "$input" "$output"
}

source_number=0
successful_downloads=0

while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//$'\r'/}"
    line="${line#$'\xef\xbb\xbf'}"

    # Ignore empty lines and comments in sources.txt.
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" == \#* ]] && continue

    line="$(printf '%s' "$line" |
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

    if [[ ! "$line" =~ ^https?://[^[:space:]]+$ ]]; then
        printf 'Invalid source URL: %s\n' "$line" >&2
        printf '%s\tinvalid-source-url\t%s\n' \
            "sources.txt" " $line" >> "$REJECTED"
        continue
    fi

    source_number=$((source_number + 1))

    if download_source "$source_number" "$line"; then
        printf '%s\n' "$line" > "$RAW_DIR/$source_number.url"
        successful_downloads=$((successful_downloads + 1))
    fi
done < "$SOURCE_FILE"

(( successful_downloads > 0 )) ||
    die "no sources downloaded successfully"

# Sanitize downloaded lists.
for input in "$RAW_DIR"/*.txt; do
    [[ -f "$input" ]] || continue

    id="$(basename "$input" .txt)"
    source="$(cat "$RAW_DIR/$id.url")"

    sanitize_file \
        "$input" \
        "$CLEAN_DIR/$id.txt" \
        "$source" >/dev/null
done

# Sanitize optional custom rules.
if [[ -s "$CUSTOM_FILE" ]]; then
    sanitize_file \
        "$CUSTOM_FILE" \
        "$CLEAN_DIR/custom.txt" \
        "custom-rules.txt" >/dev/null
fi

COMBINED="$BUILD_DIR/combined.txt"
SORTED="$BUILD_DIR/sorted.txt"

: > "$COMBINED"

for file in "$CLEAN_DIR"/*.txt; do
    [[ -f "$file" ]] || continue
    cat "$file" >> "$COMBINED"
done

# Deterministic output:
# - remove CR characters
# - remove blank lines
# - remove duplicate rules
# - use stable byte ordering
sed 's/\r$//' "$COMBINED" |
    sed '/^[[:space:]]*$/d' |
    LC_ALL=C sort -u > "$SORTED"

rule_count="$(wc -l < "$SORTED" | tr -d ' ')"

(( rule_count > 0 )) ||
    die "zero compatible legacy Bromite rules produced"

{
    printf '! Legacy Bromite network filters\n'
    printf '! CSS, scriptlets, regex, and filter options removed\n'
    printf '! Generated: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    cat "$SORTED"
} > "$tmp_output"

mv -f "$tmp_output" "$OUTPUT_FILE"

rejected_count="$(cat "$BUILD_DIR/rejected-count.txt" 2>/dev/null || printf '0')"
download_error_count="$(wc -l < "$DOWNLOAD_ERRORS" | tr -d ' ')"

printf '\nBuild completed successfully\n'
printf 'Output:           %s\n' "$OUTPUT_FILE"
printf 'Compatible rules: %s\n' "$rule_count"
printf 'Rejected rules:   %s\n' "$rejected_count"
printf 'Failed sources:   %s\n' "$download_error_count"
printf 'Rejected report:  %s\n' "$REJECTED"
printf 'Download report:  %s\n' "$DOWNLOAD_ERRORS"
