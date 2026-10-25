<script>
  // Entity graph (Cytoscape.js, bundled and lazy-loaded so the main app stays small), first-seen
  // baselines, and the detection-rule backtest. Every node label is log-derived: Cytoscape draws on
  // canvas (no HTML injection) and the accessible table below renders through Svelte's escaping.
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { del, get, post } from '$lib/api.js';
  import { canEdit } from '$lib/state.svelte.js';
  import ErrorBox from '$c/ErrorBox.svelte';
  let inc = $state(page.url.searchParams.get('incident') || ''), entity = $state(''), g = $state(null), error = $state(null);
  let el = $state(), cy, focus = $state(null), baselines = $state([]), bq = $state('');
  let rule = $state(`title: SSH logins that failed for deploy\ndetection:\n  selection:\n    rule.groups|contains: authentication_failed\n    data.dstuser: deploy\n  condition: selection`);
  let bt = $state(null), btErr = $state(null);
  const COLORS = { ip: '#8F1C13', user: '#1F4677', host: '#0B6E69', process: '#6B5200' };

  async function loadGraph() {
    error = null;
    try {
      g = await get(inc ? `/api/graph?incident_id=${encodeURIComponent(inc)}` : `/api/graph?entity=${encodeURIComponent(entity)}`);
      const { default: cytoscape } = await import('cytoscape');
      cy?.destroy();
      cy = cytoscape({ container: el,
        elements: [...g.nodes.map((n) => ({ data: { id: n.id, label: `${n.kind}: ${n.label}`, kind: n.kind, focus: n.focus ? 1 : 0, size: 18 + Math.min(30, Math.log2(1 + n.alerts) * 5) } })),
          ...g.edges.map((e, k) => ({ data: { id: `e${k}`, source: e.source, target: e.target, label: `${e.relation} (${e.count})` } }))],
        style: [{ selector: 'node', style: { 'background-color': (n) => COLORS[n.data('kind')], label: 'data(label)', 'font-size': 10, color: '#56625F', width: 'data(size)', height: 'data(size)', 'text-valign': 'bottom', 'text-margin-y': 4 } },
          { selector: 'node[focus = 1]', style: { 'border-width': 3, 'border-color': '#16201E' } },
          { selector: 'edge', style: { width: 1.5, 'line-color': '#C2CBC6', 'target-arrow-shape': 'triangle', 'target-arrow-color': '#C2CBC6', 'curve-style': 'bezier', label: 'data(label)', 'font-size': 8, color: '#56625F' } },
          { selector: '.faded', style: { opacity: 0.15 } }],
        layout: { name: 'cose', animate: false, padding: 24 } });
      cy.on('tap', 'node', (ev) => {
        const n = ev.target; focus = g.nodes.find((x) => x.id === n.id());
        cy.elements().addClass('faded'); n.closedNeighborhood().removeClass('faded');
      });
      cy.on('tap', (ev) => { if (ev.target === cy) { cy.elements().removeClass('faded'); focus = null; } });
    } catch (e) { error = e; }
  }
  async function loadBaselines() { baselines = await get(`/api/baselines${bq ? '?entity=' + encodeURIComponent(bq) : ''}`).catch(() => []); }
  async function runBacktest() { btErr = null; try { bt = await post('/api/backtest', { rule, days: 30 }); } catch (e) { btErr = e; } }
  let risk = $state([]);
  const loadRisk = async () => { risk = await get('/api/risk').catch(() => []); };
  onMount(() => { if (inc) loadGraph(); loadBaselines(); loadRisk(); return () => cy?.destroy(); });
</script>
<svelte:head><title>Investigate · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="stack" style="gap:6px"><h1>Investigate</h1><p class="muted">Who touched what in a 24-hour window, what is normal for an account, and what a new rule would have caught.</p></header>
  <section class="card pad stack" aria-labelledby="gh"><h2 id="gh">Entity graph</h2>
    <form class="row" onsubmit={(e) => { e.preventDefault(); loadGraph(); }}>
      <div class="field"><label for="inc">Incident number</label><input id="inc" type="text" inputmode="numeric" bind:value={inc} /></div>
      <span class="muted">or</span>
      <div class="field grow" style="max-width:320px"><label for="ent">Entity (ip:…, user:…, host:…)</label><input id="ent" type="text" placeholder="ip:203.0.113.45" bind:value={entity} oninput={() => (inc = '')} /></div>
      <button class="btn primary" style="align-self:flex-end">Draw graph</button>
    </form>
    <ErrorBox {error} />
    <div bind:this={el} class="graph" role="img" aria-label="Entity graph. The same data is in the table below."></div>
    {#if g}
      <p class="small">Blast radius: {g.blast_radius_hosts.length} host{g.blast_radius_hosts.length === 1 ? '' : 's'} ({g.blast_radius_hosts.map((h) => h.slice(5)).join(', ')}).
        {#if focus}Selected <strong>{focus.kind} {focus.label}</strong>: {focus.alerts} alerts, incidents {#each focus.incidents as id}<a href="/incidents/{id}">#{id}</a> {/each}{:else}Click a node to highlight what it touched.{/if}</p>
      <details><summary class="small">Relationships as a table</summary><div class="table-wrap"><table>
        <thead><tr><th>From</th><th>Relation</th><th>To</th><th class="num">Alerts</th><th>Incidents</th></tr></thead>
        <tbody>{#each g.edges as e}<tr><td class="mono">{e.source}</td><td>{e.relation}</td><td class="mono">{e.target}</td><td class="num">{e.count}</td>
          <td>{#each e.incidents as id}<a href="/incidents/{id}">#{id}</a> {/each}</td></tr>{/each}</tbody></table></div></details>
    {/if}
  </section>
  <section class="card pad stack" aria-labelledby="rk"><h2 id="rk">Entity risk</h2>
    <p class="muted small">Every kept alert adds decaying points to its user, host and source IP. When an entity crosses the threshold with alerts from two or more separate incidents, Sieve raises one incident that lists what contributed: slow attacks made of harmless-looking alerts.</p>
    <div class="table-wrap"><table><thead><tr><th>Entity</th><th class="num">Points</th><th>Recent contributors</th><th></th></tr></thead><tbody>
      {#each risk as r}<tr><td class="mono">{r.entity}</td><td class="num" class:error={r.points >= r.threshold}>{r.points} / {r.threshold}</td>
        <td class="small">{r.contributors.slice(-4).map((c) => `${c.rule} (+${c.points})`).join(', ')}</td>
        <td>{#if canEdit()}<button class="btn small" onclick={async () => { await del(`/api/risk/${encodeURIComponent(r.entity)}`).catch(() => {}); loadRisk(); }}>Reset</button>{/if}</td></tr>
      {:else}<tr><td colspan="4" class="empty">No risk accumulated.</td></tr>{/each}</tbody></table></div>
  </section>
  <section class="card pad stack" aria-labelledby="bh"><h2 id="bh">First-seen baselines</h2>
    <div class="row"><div class="field grow" style="max-width:320px"><label for="bq">Filter by entity</label><input id="bq" type="search" placeholder="user:deploy" bind:value={bq} oninput={loadBaselines} /></div></div>
    <div class="table-wrap"><table><thead><tr><th>Entity</th><th>Feature</th><th>First seen</th><th>Last seen</th><th class="num">Times</th></tr></thead>
      <tbody>{#each baselines.slice(0, 50) as b}<tr><td class="mono">{b.entity}</td><td class="mono">{b.feature}</td><td>{new Date(b.first_seen).toLocaleString()}</td><td>{new Date(b.last_seen).toLocaleString()}</td><td class="num">{b.count}</td></tr>
      {:else}<tr><td colspan="5" class="empty">No baseline records yet.</td></tr>{/each}</tbody></table></div>
  </section>
  {#if canEdit()}
  <section class="card pad stack" aria-labelledby="rh"><h2 id="rh">Test a detection rule</h2>
    <p class="muted">Paste a Sigma rule or one Wazuh &lt;rule&gt;. Sieve replays it over the last 30 days of stored alerts. Nothing is deployed.</p>
    <label class="sr-only" for="rule">Rule</label><textarea id="rule" bind:value={rule}></textarea>
    <button class="btn primary" onclick={runBacktest} style="align-self:flex-start">Backtest</button>
    <ErrorBox error={btErr} />
    {#if bt}<div class="kpis card"><div class="kpi"><span class="small muted">Would have fired</span><span class="v">{bt.would_fire}</span></div>
      <div class="kpi"><span class="small muted">On suppressed (benign) alerts</span><span class="v">{bt.on_suppressed_alerts}</span></div>
      <div class="kpi"><span class="small muted">Incidents touched</span><span class="v">{bt.incidents_touched}</span></div>
      <div class="kpi"><span class="small muted">Share benign</span><span class="v">{bt.pct_benign}%</span></div></div>
      {#if bt.would_have_caught.length}<p>Would have caught: {#each bt.would_have_caught as x}<a href="/incidents/{x.id}">#{x.id} {x.title}</a> ({x.band}) {/each}</p>{/if}
      <p class="small muted">{bt.note}</p>{/if}
  </section>
  {/if}
</div>
<style>.graph { height: 420px; border: 1px solid var(--line); border-radius: 8px; background: var(--ground); }</style>
