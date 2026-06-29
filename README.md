# zedsuprise

A static, single-page web app hosted on Cloudflare Pages.

**Live:** https://zedsuprise.pages.dev

## Overview

A dependency-free, media-rich site: one long-scroll page of photo galleries, native video, and interactive widgets, served as static assets with a little edge logic on top. No framework and no build step — hand-written HTML, CSS, and vanilla JavaScript, with imagery and video delivered from Cloudflare R2.

## Stack

| Layer | Tech |
|---|---|
| Hosting | Cloudflare Pages (static assets + Pages Functions) |
| Frontend | Vanilla HTML · CSS · JavaScript |
| Media | Cloudflare R2 — images + native HTML5 video (HTTP range streaming) |
| Analytics | PostHog (edge-proxied) |

## Notes

- No framework or bundler — a single shell file plus self-contained enhancement scripts.
- Interactive widgets, all vanilla JS: a shared pinch / wheel / double-tap zoom-and-pan engine across the photo viewers, a 3D tilt-and-flip card, a paged document viewer, and per-photo copy-link sharing.
- Lightweight Pages Functions handle media delivery and proxy analytics at the edge.
- Hardened response headers (CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, referrer policy) and immutable asset caching via `_headers`.

## Project structure

```
index.html      the page
functions/      Cloudflare Pages Functions (edge logic + media)
photos/         imagery
_headers        security + caching headers
404.html        themed not-found page
robots.txt      noindex
wrangler.toml   Pages config
```

## License

Copyright © 2026 the zedsuprise authors. **All rights reserved** — see [LICENSE](LICENSE).

The code is here to browse and reference; it (and the media — photos and video) is not licensed for reuse, in whole or in part, without prior written permission.
