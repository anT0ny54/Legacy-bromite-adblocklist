# Filter Lists

Comprehensive blocklist for ads, privacy & annoyance filter list — auto-compiled from trusted sources into a single file.

## Subscribe

Add this **one URL** to your browser:

```
https://raw.githubusercontent.com/anT0ny54/filter-lists/refs/heads/main/filters.txt
```

### uBlock Origin, ABP and etc
1. Dashboard → Filter lists → Import → paste the URL above
2. Click "Apply changes"


## How It Works

A GitHub Action runs daily (fully automatic, zero manual work):
1. Downloads all sources from `sources.txt` (with 90s per-URL timeout)
2. Resolves `!#include` directives recursively (up to 3 levels deep)
3. Validates downloads (rejects HTML error pages, empty files, binary content)
4. Strips comments and headers
5. Deduplicates with `sort -u`
6. Appends custom rules from `custom-rules.txt`
7. Commits updated `filters.txt` only if content changed

## Customization

- **Add/remove sources**: Edit `sources.txt`
- **Add custom rules**: Edit `custom-rules.txt`
- **Force rebuild**: Actions → Update Filter List → Run workflow

#### :department_store: **My Free DNS Server, free** <a name="dns server"></a>

On [My Free DNS] you can use HaGeZi Blocklists Multi Pro + TIF.

| Hagezi Blocklists | DNS-over-HTTPS |
|:---------------|:---------------|
| Multi Pro + TIF | `https://freedns-six.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |


# ⚡ Bandwidth Hero Server

> A lightweight image optimization proxy designed to reduce bandwidth usage and speed up web browsing.

Bandwidth Hero Server fetches remote images, compresses them, and delivers optimized versions to the client. It helps reduce data consumption while improving loading performance.

🖥️ If you want, you can see this [Bandwidth Hero](https://bhserv.netlify.app/)


## Legal Disclaimer

- **Personal use only** — maintained exclusively for the repository owner's personal browsing on personal devices. Not a product, not a service, not offered to the public.
- **No affiliation** — does not represent any employer, organization, or professional entity (past, present, or future).
- **Third-party content** — all filter rules originate from independent, publicly available open-source projects. All IP rights remain with their respective authors. No claim of authorship or owners[...]
- **No distribution or recommendation** — the owner does not encourage, recommend, or endorse use by any third party.
- **No commercial use** — generates no revenue, accepts no payments, serves no business purpose.
- **No intent to cause harm** — sole purpose is personal privacy and security. No intent to cause economic loss to any advertiser, publisher, or ad network.
- **Right to privacy** — personal content filtering is a recognized lawful exercise of individual privacy rights under GDPR (EU), DPDPA (India), CCPA (USA), PIPEDA (Canada), UK GDPR, nDSG (Switz[...]
- **No warranty** — provided "as-is" without warranties of any kind. Use at your own risk.
- **Compliance** — users are solely responsible for compliance with their local laws.

See [LICENSE](LICENSE) for comprehensive legal terms covering all jurisdictions.

## Supporting My Project

If you are interested in supporting the project you can donate :
 - Bitcoin: 1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP
