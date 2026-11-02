<img width="1001" height="756" alt="image" src="https://github.com/user-attachments/assets/6556ae4b-3d0c-4787-89c2-a7df173f8f5b" />

# DNS Checker

A bare-bones, mobile-first DNS lookup tool with a black-and-white interface. It queries Google (8.8.8.8) and Cloudflare (1.1.1.1) over DNS-over-HTTPS, compares their selected records, and displays the selected results inside one card:

- A records
- MX records, with each MX host's A records available behind a Show button
- NS records, with each nameserver's A records available behind a Show button
- HTTP response headers (status, HTTP version, web server, PHP version, compression, HSTS, CDN/cache)
- SPF (TXT)
- DKIM (TXT, auto-scanned common selectors)
- DMARC (TXT)
- PTR records for A and MX addresses
- Domain registrar via RDAP

## Run

```bash
npm start
```

Open <http://127.0.0.1:3000>.

No dependencies are required. Use Node.js 26 LTS or newer.

The server uses only built-in Node.js APIs (`node:http`, `node:fs/promises`, `node:url`, global `fetch`, and `AbortSignal.timeout`), all supported by Node.js 26 LTS.

## Notes

- The domain field starts empty, and no lookup runs until the form is submitted.
- Checkboxes are visible before the first lookup. A, MX, and NS are checked by default; HTTP headers, SPF, DKIM, DMARC, PTR, and Domain registrar start unchecked.
- Only checked record types are queried. Changing a checkbox after a lookup refreshes the results with the new selection.
- Every lookup checks both Google and Cloudflare and compares the selected resolver-dependent records. Matching results show no comparison message; differences are highlighted in red. Legacy Google Workspace MX hosts (`aspmx.l.google.com`, `aspmx1-5.googlemail.com`, `alt1-5.aspmx.l.google.com`, `smtp.google.com`) are ignored during MX comparison.
- The record count and “Copy shown” action follow the visible selections.
- A small Node server handles DNS-over-HTTPS requests server-side, avoiding browser CORS limitations and keeping the page itself dependency-free.
- DNS values are rendered with `textContent`, never inserted as HTML.
- DKIM selectors are scanned automatically. Empty `p=` values are treated as revoked keys rather than usable records.
- No lookups are logged or stored by the app.
- Port and bind address can be changed with `PORT` and `HOST` environment variables.
- The API still accepts an optional `resolver=google|cloudflare` parameter for compatibility, but the UI always checks both and uses Google as the primary display.

## Test

```bash
curl "http://127.0.0.1:3000/api/dns?domain=google.com&resolver=google"
curl "http://127.0.0.1:3000/api/dns?domain=google.com&resolver=cloudflare"
```
