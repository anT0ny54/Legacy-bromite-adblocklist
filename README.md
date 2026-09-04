# 🛡️ Filter Lists

A comprehensive, auto-aggregated blocklist designed to eliminate ads, protect privacy, and remove web annoyances, etc.

## Subscribe

Add the following URL to your browser or ad-blocker:

```
https://raw.githubusercontent.com/anT0ny54/Legacy-bromite-adblocklist/refs/heads/main/filters.txt
```

### uBlock Origin, ABP, and others
1. Open **Dashboard** $\rightarrow$ **Filter lists** $\rightarrow$ **Import**.
2. Paste the URL provided above.
3. Click **Apply changes**.

## How It Works

The list is maintained by a fully automated GitHub Action that runs daily:
1. **Aggregation**: Downloads all sources listed in `sources.txt` (with a 90s per-URL timeout).
2. **Recursive Resolution**: Resolves `!#include` directives up to 3 levels deep.
3. **Validation**: Rejects empty files, binary content, or HTML error pages.
4. **Cleanup**: Strips comments and headers for maximum efficiency.
5. **Deduplication**: Uses `sort -u` to remove redundant rules.
6. **Customization**: Appends user-defined rules from `custom-rules.txt`.
7. **Deployment**: Commits the updated `filters.txt` only if changes are detected.

## Customization

- **Manage Sources**: Edit `sources.txt` to add or remove lists.
- **Personal Rules**: Edit `custom-rules.txt` to add your own filters.
- **Manual Update**: Navigate to **Actions** $\rightarrow$ **Update Filter List** $\rightarrow$ **Run workflow**.

## 🌐 Free DNS Services

High-performance DNS utilizing HaGeZi Blocklists (Multi Pro + TIF).

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns-six.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |

---

# ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/)

## Legal Disclaimer

- **Personal Use Only**: This project is maintained exclusively for the repository owner's personal browsing on personal devices. It is not a product, not a service, and is not offered to the general public.
- **No Affiliation**: This project does not represent any employer, organization, or professional entity.
- **Third-Party Content**: All filter rules originate from independent, open-source projects. All intellectual property rights remain with their respective authors.
- **No Endorsement**: The owner does not encourage, recommend, or endorse the use of these tools by third parties.
- **Non-Commercial**: This project generates no revenue, accepts no payments, and serves no business purpose.
- **No Intent to Harm**: The sole purpose of this project is personal privacy and security. There is no intent to cause economic loss to any advertiser, publisher, or ad network.
- **Right to Privacy**: Personal content filtering is a recognized exercise of individual privacy rights under global regulations, including GDPR (EU), DPDPA (India), CCPA (USA), PIPEDA (Canada), UK GDPR, and nDSG (Switzerland).
- **No Warranty**: Provided "as-is" without warranties of any kind. Use at your own risk.
- **Compliance**: Users are solely responsible for ensuring compliance with their local laws.

Refer to the [LICENSE](LICENSE) for comprehensive legal terms covering all jurisdictions.

## Supporting the Project

If you find this project useful, donations are appreciated:
- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`
  
