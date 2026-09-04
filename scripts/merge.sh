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
MAX_OUTPUT_BYTES="${MAX_OUTPUT_BYTES:-20971520}"
CURL_TIMEOUT="${CURL_TIMEOUT:-120}"

USER_AGENT="${USER_AGENT:-legacy-bromite-filter-builder/2.0}"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 ||
        die "missing required command: $1"
}

for command in curl awk sed sort grep head tr wc mktemp cat; do
    need "$command"
done

[[ -f "$SOURCE_FILE" ]] ||
    die "missing source file: $SOURCE_FILE"

mkdir -p "$(dirname -- "$OUTPUT_FILE")"

rm -rf "$BUILD_DIR"
mkdir -p "$RAW_DIR" "$CLEAN_DIR"

REJECTED="$BUILD_DIR/rejected.txt"
DOWNLOAD_ERRORS="$BUILD_DIR/download-errors.txt"
COMBINED="$BUILD_DIR/combined.txt"
SORTED="$BUILD_DIR/sorted.txt"

printf '# source\treason\trule\n' > "$REJECTED"
: > "$DOWNLOAD_ERRORS"
: > "$COMBINED"

tmp_output="$(mktemp "${OUTPUT_FILE}.tmp.XXXXXX")"

cleanup() {
    rm -f "$tmp_output"
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
        --user-agent "$USER_AGENT" \
        "$url" \
        --output "$output"; then

        printf 'DOWNLOAD_FAILED\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f "$output"
        return 1
    fi

    if [[ ! -s "$output" ]]; then
        printf 'EMPTY\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f "$output"
        return 1
    fi

    # Reject common HTML error pages.
    if head -c 4096 "$output" |
        tr '[:upper:]' '[:lower:]' |
        grep -Eq '<html|<!doctype|access denied|error 404|rate limit exceeded'; then

        printf 'HTML_OR_ERROR\t%s\n' "$url" >> "$DOWNLOAD_ERRORS"
        rm -f "$output"
        return 1
    fi

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

    function valid_domain(value,    count, parts, i, part) {
        # Lowercase ASCII hostnames only.
        if (value !~ /^[A-Za-z0-9.-]+$/)
            return 0

        if (value ~ /^\./ || value ~ /\.$/)
            return 0

        if (value ~ /\.\./)
            return 0

        count = split(value, parts, ".")

        for (i = 1; i <= count; i++) {
            part = parts[i]

            if (part == "")
                return 0

            if (part ~ /^\-/ || part ~ /\-$/)
                return 0

            if (part !~ /^[A-Za-z0-9-]+$/)
                return 0
        }

        return 1
    }

    function valid_domain_anchor(value, normalized, domain) {
        # Accept only a validated domain anchor:
        # ||example.com^
        # ||example.com/path
        # ||example.com*
        # @@||example.com^

        normalized = value

        # Remove the exception prefix.
        sub(/^\@\@/, "", normalized)

        # Must start with ||.
        if (normalized !~ /^\|\|/)
            return 0

        # Extract the hostname before ^, /, or *.
        domain = normalized
        sub(/^\|\|/, "", domain)
        sub(/[\/\^\*].*$/, "", domain)

        if (!valid_domain(domain))
            return 0

        # Require a valid network-filter suffix.
        return normalized ~ /^\|\|[A-Za-z0-9.-]+(\^|\/|\*)/
    }

    function valid_http_rule(value) {
        # Accept:
        # |https://example.com/ad.js
        # https://example.com/ad.js
        # @@|https://example.com/ad.js
        # @@https://example.com/ad.js
        return value ~ /^(\@\@)?\|https?:\/\/[^|[:space:]]+$/ ||
               value ~ /^(\@\@)?https?:\/\/[^[:space:]]+$/
    }

    function valid_path_rule(value) {
        # Accept simple path filters such as:
        # /ads/banner
        # /advertising/
        #
        # A rule beginning and ending with "/" is rejected separately
        # because that represents a regular-expression filter.
        return value ~ /^(\@\@)?\/[A-Za-z0-9._~:/?&=%+\-]+$/
    }

    function valid_plain_rule(value) {
        # Plain substring filters are intentionally restricted.
        # Operators are not allowed here because malformed ABP syntax
        # could otherwise pass through accidentally.
        return value ~ /^[A-Za-z0-9._~:/?&=%+\-]+$/ &&
               value ~ /[A-Za-z0-9]/ &&
               value !~ /^\.+$/ &&
               value !~ /^-+$/
    }

    {
        original = $0

        # Remove CR and UTF-8 BOM.
        sub(/\r$/, "", $0)
        sub(/^\357\273\277/, "", $0)

        line = $0
        gsub(/^[ \t]+|[ \t]+$/, "", line)

        if (line == "")
            next

        # Standard ABP comments and metadata.
        if (line ~ /^!/)
            next

        if (line ~ /^\[Adblock/) {
            reject("metadata", original)
            next
        }

        # Reject all cosmetic, HTML, scriptlet, and procedural syntax.
        if (line ~ /##|#@#|#\?#|#\$#|#%#|#\^#|#@%\?#/) {
            reject("cosmetic-or-procedural-filter", original)
            next
        }

        if (line ~ /\+js\(|:has-text\(|:contains\(|:matches-css\(|:xpath\(|:style\(/) {
            reject("scriptlet-or-procedural-filter", original)
            next
        }

        # Reject all filter options for lowest-risk legacy compatibility.
        if (line ~ /\$/) {
            reject("filter-options-not-allowed", original)
            next
        }

        # Reject regular-expression filters.
        if (line ~ /^\/.*\/$/) {
            reject("regular-expression-filter", original)
            next
        }

        # Reject control characters.
        if (line ~ /[\001-\010\013\014\016-\037\177]/) {
            reject("control-character", original)
            next
        }

        # Reject non-ASCII input.
        # This is intentionally strict for predictable legacy parsing.
        if (line ~ /[^\041-\176\t ]/) {
            reject("non-ascii-character", original)
            next
        }

        # Convert hosts-file entries:
        # 0.0.0.0 example.com
        # 127.0.0.1 example.com
        # ::1 example.com
        #
        # Optional comments after the hostname are accepted.
        if (line ~ /^[ \t]*(0\.0\.0\.0|127\.0\.0\.1|::1)[ \t]+/) {
            count = split(line, fields, /[ \t]+/)

            if (count >= 2 &&
                fields[1] ~ /^(0\.0\.0\.0|127\.0\.0\.1|::1)$/ &&
                valid_domain(fields[2]) &&
                (count == 2 || fields[3] ~ /^#/)) {

                print "||" tolower(fields[2]) "^"
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

        # Reject unsupported or dangerous schemes.
        if (line ~ /^(file|data|javascript|about|chrome|chrome-extension):/) {
            reject("unsupported-scheme", original)
            next
        }

        # Reject angle brackets and backslashes.
        if (line ~ /[<>\\]/) {
            reject("unsafe-character", original)
            next
        }

        # Exception rules must use a recognized strict form.
        if (line ~ /^\@\@/) {
            if (valid_domain_anchor(line) ||
                valid_http_rule(line) ||
                valid_path_rule(line)) {
                print line
            } else {
                reject("invalid-exception-rule", original)
            }

            next
        }

        # Domain-anchored network rules.
        if (valid_domain_anchor(line)) {
            print line
            next
        }

        # HTTP and HTTPS rules.
        if (valid_http_rule(line)) {
            print line
            next
        }

        # Simple path rules.
        if (valid_path_rule(line)) {
            print line
            next
        }

        # Strict plain substring rules.
        if (valid_plain_rule(line)) {
            print line
            next
        }

        reject("unknown-or-unsafe-syntax", original)
    }
    ' "$input" > "$output"
}

source_number=0
successful_downloads=0

while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//$'\r'/}"
    line="${line#$'\xef\xbb\xbf'}"

    # Trim leading and trailing whitespace.
    line="$(printf '%s' "$line" |
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

    # Ignore empty lines and comments.
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue

    if [[ ! "$line" =~ ^https?://[^[:space:]]+$ ]]; then
        printf '%s\tinvalid-source-url\t%s\n' \
            "sources.txt" "$line" >> "$REJECTED"
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

# Sanitize downloaded sources.
for input in "$RAW_DIR"/*.txt; do
    [[ -f "$input" ]] || continue

    id="$(basename "$input" .txt)"
    source="$(cat "$RAW_DIR/$id.url")"

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

# Combine all sanitized rules.
for file in "$CLEAN_DIR"/*.txt; do
    [[ -f "$file" ]] || continue
    cat "$file" >> "$COMBINED"
done

# Remove blank lines, normalize CRLF, sort, and deduplicate.
sed 's/\r$//' "$COMBINED" |
    sed '/^[[:space:]]*$/d' |
    LC_ALL=C sort -u > "$SORTED"

rule_count="$(wc -l < "$SORTED" | tr -d ' ')"

(( rule_count > 0 )) ||
    die "zero compatible legacy Bromite rules produced"

{
    printf '! Legacy Bromite network filters\n'
    printf '! Cosmetic, scriptlet, procedural, regex, and option rules removed\n'
    printf '! Generated by filter-lists\n'
    cat "$SORTED"
} > "$tmp_output"

output_bytes="$(wc -c < "$tmp_output" | tr -d ' ')"

(( output_bytes <= MAX_OUTPUT_BYTES )) || {
    die "filters.txt is ${output_bytes} bytes; maximum allowed is ${MAX_OUTPUT_BYTES} bytes"
}

mv -f "$tmp_output" "$OUTPUT_FILE"

rejected_count="$(
    awk 'NR > 1 { count++ } END { print count + 0 }' "$REJECTED"
)"

download_error_count="$(
    wc -l < "$DOWNLOAD_ERRORS" | tr -d ' '
)"

printf '\nBuild completed successfully\n'
printf 'Output:           %s\n' "$OUTPUT_FILE"
printf 'Compatible rules: %s\n' "$rule_count"
printf 'Output size:      %s bytes\n' "$output_bytes"
printf 'Rejected rules:   %s\n' "$rejected_count"
printf 'Failed sources:   %s\n' "$download_error_count"
printf 'Rejected report:  %s\n' "$REJECTED"
printf 'Download report:  %s\n' "$DOWNLOAD_ERRORS"
