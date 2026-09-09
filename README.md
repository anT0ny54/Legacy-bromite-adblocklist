# Legacy Bromite / Cromite Filter List

A focused filter-list builder for the **legacy Bromite-style Chromium subresource adblock engine**.

The project downloads selected ABP / EasyList / EasyPrivacy / AdGuard / uBlock source lists, keeps only a conservative network-filter subset, normalizes it, removes duplicates, and publishes `filters.txt`.


## Target

This repository targets the **legacy Bromite adblock path**, i.e. Chromium's subresource filter/ruleset pipeline. Bromite documents custom filters as a filter-list input that can be converted with `ruleset_converter`; Bromite's legacy engine does not support CSS rules.

`filters.txt` is therefore an **intermediate filter-list text file**, not the final binary `filters.dat`/unindexed ruleset.

Example conversion:

```bash
ruleset_converter \
  --input_format=filter-list \
  --output_format=unindexed-ruleset \
  --input_files=filters.txt \
  --output_file=filters.dat
```

The same compatibility target is useful when the legacy Bromite-style adblocker is enabled in Cromite. Cromite documents the legacy engine separately from its newer Adblock Plus engine.


## What `filters.txt` contains

The builder intentionally keeps only conservative **network filtering rules**:

- `||example.com^`
- `@@||example.com^`
- `||example.com/path/*`
- `@@||example.com/path/*`
- simple `|https://example.com/path|` URL-anchored rules
- common hosts-file entries converted to `||domain^`

The output deliberately removes:

- cosmetic/CSS selectors
- scriptlets
- procedural filters
- regular-expression filters
- filter options/modifiers (`$...`)
- unsupported schemes
- malformed host entries
- non-ASCII/control-character rules

This is intentional: **the goal is compatibility and predictable conversion, not preservation of every uBlock/AdGuard feature.**


## Why this design

Modern filter lists contain syntax that the legacy Chromium/Bromite subresource filter cannot consume directly. Bromite's documented workflow is to feed a filter-list into `ruleset_converter`.

The project therefore performs the cleanup *before* conversion instead of pretending that all upstream syntax is valid for the legacy engine.


## Subscribe

Add the following URL to your browser or ad-blocker:

```
https://raw.githubusercontent.com/anT0ny54/Legacy-bromite-adblocklist/main/filters.txt
```

### uBlock Origin, ABP, and others
1. Open **Dashboard** $\rightarrow$ **Filter lists** $\rightarrow$ **Import**.
2. Paste the URL provided above.
3. Click **Apply changes**.


## Build

```bash
bash scripts/merge.sh
```

The build produces:

```text
filters.txt
build/rejected.txt
build/download-errors.txt
build/source-counts.txt
```


### Optional strict source availability

```bash
REQUIRE_ALL_SOURCES=1 bash scripts/merge.sh
```


### Optional Chromium converter validation

If `ruleset_converter` is installed:

```bash
VALIDATE_WITH_RULESET_CONVERTER=1 \
RULESET_CONVERTER=/path/to/ruleset_converter \
bash scripts/merge.sh
```

The converter is then used as a final compatibility gate.


## Custom rules

Put personal network rules in `custom-rules.txt`.

Keep them within the same legacy-compatible grammar. The file is sanitized by the exact same parser as downloaded lists.


## Source management

Edit `sources.txt` to add/remove upstream lists. One HTTPS URL per line; `#` starts a comment.

The downloader has limits for:

- per-source size
- total downloaded size
- source count
- connection timeout
- total request timeout
- retry count

Downloaded sources are also checked for common HTML error pages before parsing.


## Validation

After generation:

```bash
tests/validate-filters.sh filters.txt
```

For the strongest validation, also run the real Chromium `ruleset_converter` because that is the component ultimately consuming the filter-list format.


## Important limitation

This repository is **not** a full uBlock Origin, AdGuard, or modern Adblock Plus compiler. A source rule that depends on cosmetic filtering, scriptlets, procedural selectors, regex, or unsupported modifiers is intentionally rejected rather than silently producing an invalid legacy rule.

That loss is preferable to shipping a `filters.txt` that looks valid but fails during Bromite conversion.


## 🌐 Free DNS Services

High-performance DNS utilizing HaGeZi Blocklists (Multi Pro + TIF).

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns.koyeb.app/dns-query` (Recommended) |
| Multi Pro + TIF | `https://freedns-six.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |

---

# ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/)


## License

See [LICENSE](LICENSE).

Third-party filter lists remain subject to their respective licenses and terms.


## Supporting the Project

If you find this project useful, donations are appreciated:
- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`
  
  