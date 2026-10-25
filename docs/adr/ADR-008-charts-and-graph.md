# ADR-008: Hand-written SVG charts; Cytoscape lazy-loaded for the entity graph

**Date:** 2026-10-17 · **Status:** Accepted

The research doc names Apache ECharts. The four charts needed (line, bar, stacked bar) are a small SVG component
(`Chart.svelte`) with an accessible label and a "show as table" fallback, which keeps the initial bundle small.
Cytoscape.js is used for the entity graph as specified, but bundled (no CDN, keeping the CSP) and loaded only
on the Investigate page. Whole-app JS is 215 KB gzipped including Cytoscape. Revisit if richer charts are needed.
