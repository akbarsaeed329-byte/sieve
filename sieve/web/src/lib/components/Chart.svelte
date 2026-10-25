<script>
  // Dependency-free accessible SVG chart (line or bar, optional stacked bars). ADR-008.
  let { title, labels = [], series = [], kind = 'line', stacked = false, unit = '' } = $props();
  const W = 640, H = 220, P = { l: 44, r: 12, t: 12, b: 28 };
  const iw = W - P.l - P.r, ih = H - P.t - P.b;
  let max = $derived(Math.max(1, ...(stacked
    ? labels.map((_, i) => series.reduce((a, s) => a + (s.values[i] || 0), 0))
    : series.flatMap((s) => s.values))));
  let step = $derived(labels.length > 1 ? iw / (labels.length - 1) : iw);
  let bw = $derived(Math.max(4, (iw / Math.max(1, labels.length)) * (stacked ? 0.6 : 0.7 / Math.max(1, series.length))));
  const y = (v) => P.t + ih - (v / max) * ih;
  const ticks = $derived([0, 0.5, 1].map((f) => Math.round(max * f)));
  const short = (d) => d.slice(5);
  let summary = $derived(series.map((s) => `${s.name}: ${s.values.join(', ')}`).join('. '));
</script>
<figure class="card pad">
  <figcaption class="row between"><h3>{title}</h3>
    <span class="legend">{#each series as s}<span><i style="background:{s.color}"></i>{s.name}</span>{/each}</span>
  </figcaption>
  <svg viewBox="0 0 {W} {H}" role="img" aria-label="{title}. {summary}{unit}">
    {#each ticks as t}
      <line x1={P.l} x2={W - P.r} y1={y(t)} y2={y(t)} class="grid" />
      <text x={P.l - 6} y={y(t) + 4} text-anchor="end" class="ax">{t}</text>
    {/each}
    {#each labels as l, i}
      {#if labels.length <= 16 || i % Math.ceil(labels.length / 8) === 0}
        <text x={kind === 'bar' ? P.l + (i + 0.5) * (iw / labels.length) : P.l + i * step} y={H - 8} text-anchor="middle" class="ax">{short(l)}</text>
      {/if}
    {/each}
    {#if kind === 'line'}
      {#each series as s}
        <polyline fill="none" stroke={s.color} stroke-width="2" points={s.values.map((v, i) => `${P.l + i * step},${y(v)}`).join(' ')} />
        {#each s.values as v, i}<circle cx={P.l + i * step} cy={y(v)} r="3" fill={s.color}><title>{s.name} {labels[i]}: {v}{unit}</title></circle>{/each}
      {/each}
    {:else}
      {#each labels as l, i}
        {@const x0 = P.l + i * (iw / labels.length) + (iw / labels.length - (stacked ? bw : bw * series.length)) / 2}
        {#if stacked}
          {#each series as s, k}
            {@const below = series.slice(0, k).reduce((a, z) => a + (z.values[i] || 0), 0)}
            <rect x={x0} width={bw} y={y(below + (s.values[i] || 0))} height={(s.values[i] || 0) / max * ih} fill={s.color}><title>{s.name} {l}: {s.values[i]}</title></rect>
          {/each}
        {:else}
          {#each series as s, k}
            <rect x={x0 + k * bw} width={bw - 1} y={y(s.values[i] || 0)} height={(s.values[i] || 0) / max * ih} fill={s.color}><title>{s.name} {l}: {s.values[i]}{unit}</title></rect>
          {/each}
        {/if}
      {/each}
    {/if}
  </svg>
  <details><summary class="small muted">Show as table</summary>
    <div class="table-wrap"><table><thead><tr><th>Day</th>{#each series as s}<th class="num">{s.name}</th>{/each}</tr></thead>
      <tbody>{#each labels as l, i}<tr><td>{l}</td>{#each series as s}<td class="num">{s.values[i]}</td>{/each}</tr>{/each}</tbody></table></div>
  </details>
</figure>
<style>
  figure { margin: 0; display: flex; flex-direction: column; gap: 8px; }
  svg { width: 100%; height: auto; }
  .grid { stroke: var(--line-2); }
  .ax { fill: var(--muted); font: 11px var(--sans); }
  .legend { display: flex; gap: 12px; font-size: 12px; color: var(--muted); flex-wrap: wrap; }
  .legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 4px; vertical-align: -1px; }
</style>
