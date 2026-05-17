# raucle Cloud — waitlist site

Static Astro site for `cloud.raucle.com`. Source lives in GitHub at `craigamcw/raucle`; deploys via Cloudflare Pages on every push to `main`.

## Before you ship

Three placeholders in `src/pages/index.astro`:

1. `TALLY_FORM_ID` — create a single-field email form at https://tally.so, copy the form id from the embed URL (the part after `tally.so/embed/`).
2. `LOCATION` — the city you want in the footer ("Built solo from …").
3. LinkedIn URL in the footer `<nav>` — currently points to `craigamcw`; confirm or change.

## Local dev

```
npm install
npm run dev          # http://localhost:4321
npm run build        # outputs to dist/
```

> If `npm` errors with `Library not loaded: ...libllhttp...`, your Homebrew Node has a stale shared library. Fix with `brew reinstall llhttp node`. Cloudflare Pages CI uses its own Node 20 image and is unaffected.

## Deploy via Cloudflare Pages

These files belong at the **root** of `craigamcw/raucle` (not in a `cloud-site/` subdirectory).

One-time setup:

1. Push these files to the `main` branch of `craigamcw/raucle`.
2. Cloudflare dashboard → **Workers & Pages → Create application → Pages → Connect to Git → select `craigamcw/raucle`**.
3. Build settings:
   - **Framework preset:** Astro
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
   - **Root directory:** *(leave blank — repo root)*
   - **Environment variables:** `NODE_VERSION=20`
4. After the first deploy, project → **Custom domains → Set up a custom domain → `cloud.raucle.com`**. If `raucle.com` is on the same Cloudflare account, the CNAME record is added automatically.

Every subsequent push to `main` triggers an auto-build. PRs get preview deployments at `<branch>.<project>.pages.dev`.

## What it does

One page. Headline, lede, "what it does", "why this exists", paper callout, status (OSS live / Cloud soon), Tally waitlist embed, footer with GitHub + LinkedIn.

Voice is consistent with the founding myth: *"the standard regulated industries already demand for everything else."* Don't drift from that line — it's load-bearing.
