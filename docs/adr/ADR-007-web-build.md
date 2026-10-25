# ADR-007: SvelteKit static build, shipped in the package, strict CSP with script hashes

**Date:** 2026-10-17 · **Status:** Accepted

* The web app is SvelteKit (Svelte 5) built with adapter-static into `sieve/web/build`, served by FastAPI
  with an SPA fallback. The build is included in the Python package so `pip install` works without Node;
  Docker builds it in a Node stage; CI rebuilds it and enforces the 300 KB gzipped JS budget.
* CSP: `script-src 'self'` plus the SHA-256 hashes of SvelteKit's inline bootstrap scripts, computed from the
  built `index.html` at startup. No inline script runs unless its hash is in the policy.
* IBM Plex fonts are bundled (@fontsource), so the app makes no third-party requests (`font-src 'self'`).
* The Prometheus endpoint keeps `/metrics`; the UI's metrics page lives at `/reports` to avoid the clash.
