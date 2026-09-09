#!/usr/bin/env bash
set -Eeuo pipefail
LC_ALL=C
export LC_ALL

file="${1:-filters.txt}"
[[ -s "$file" ]] || { echo "ERROR: missing/empty filter file: $file" >&2; exit 1; }

# Header comments are allowed. Every actual rule must remain in the deliberately
# conservative legacy Bromite input grammar emitted by merge.sh.
awk '
function fail(msg) { printf "ERROR: line %d: %s\n", NR, msg > "/dev/stderr"; bad=1 }
{
  sub(/\r$/, "")
  if ($0 == "" || $0 ~ /^!/) next
  if ($0 ~ /[[:space:]]/) fail("whitespace in rule")
  if ($0 ~ /\$/) fail("modifier/options found")
  if ($0 ~ /##|#@#|#\?#|#\$#|#%#|#\^#|#@%\?#/) fail("cosmetic rule found")
  if ($0 ~ /\+js\(|:has-text\(|:contains\(|:matches-css\(|:xpath\(|:style\(/) fail("scriptlet/procedural rule found")
  if ($0 ~ /^\/.*\/$/) fail("regex rule found")
  if ($0 ~ /^@@\|\|/) {
    r=$0; sub(/^@@\|\|/, "", r)
  } else if ($0 ~ /^\|\|/) {
    r=$0; sub(/^\|\|/, "", r)
  } else if ($0 ~ /^\|https?:\/\//) {
    next
  } else {
    fail("unsupported rule prefix")
    next
  }
  host=r
  sub(/[\/?#].*$/, "", host)
  sub(/\^.*$/, "", host)
  sub(/\|.*$/, "", host)
  if (host !~ /^[A-Za-z0-9.-]+$/) fail("invalid hostname")
  if (host !~ /\./ || host ~ /^\.|\.$|\.\./) fail("invalid hostname")
}
END { exit bad+0 }
' "$file"

echo "OK: $file passes legacy Bromite input validation"
