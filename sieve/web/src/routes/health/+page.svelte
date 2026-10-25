<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  import Light from '$c/Light.svelte';
  import ErrorBox from '$c/ErrorBox.svelte';
  let h = $state(null), error = $state(null);
  async function load() { try { h = await get('/api/health/details'); error = null; } catch (e) { error = e; } }
  onMount(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); });
  const words = { green: 'All systems working', amber: 'Working, with warnings', red: 'Something needs attention', unknown: 'Unknown' };
</script>
<svelte:head><title>Health · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="stack" style="gap:6px"><h1>Health</h1>
    {#if h}<p class="row" style="font-size:15px"><Light light={h.overall} label="Overall" />{words[h.overall]} · Sieve {h.version}</p>{/if}</header>
  <ErrorBox {error} />
  {#if h}
    <p class="muted">If any part fails, Sieve still sends a plain, rule-based notification. A red AI light means summaries are paused, not alerts.</p>
    <div class="card table-wrap"><table>
      <thead><tr><th>Component</th><th>Status</th><th>Detail</th></tr></thead>
      <tbody>{#each h.components as c}<tr><td><span class="row" style="gap:8px"><Light light={c.light} label={c.name} />{c.name}</span></td>
        <td>{({green:'OK',amber:'Warning',red:'Problem',unknown:'Not configured / unknown'})[c.light]}</td>
        <td><span class="small">{c.detail}</span>{#if c.error}<br /><span class="small error">{c.error.message} {c.error.fix} ({c.error.code})</span>{/if}</td></tr>{/each}</tbody>
    </table></div>
    <section class="card kpis" aria-label="Queue and counters">
      <div class="kpi"><span class="small muted">Queue waiting</span><span class="v">{h.queue.pending}</span></div>
      <div class="kpi"><span class="small muted">Queue failed</span><span class="v">{h.queue.failed}</span></div>
      <div class="kpi"><span class="small muted">AI calls this hour</span><span class="v">{h.llm.budget.used} / {h.llm.budget.per_hour}</span></div>
      <div class="kpi"><span class="small muted">Alerts processed since start</span><span class="v">{h.metrics.alerts.toLocaleString()}</span></div>
    </section>
    <p class="small muted">Shadow mode: {h.shadow_mode ? 'on (no notifications sent)' : 'off'} · Active response: {h.active_response ? 'enabled, human approval required' : 'disabled'} · Prometheus metrics at <code>/metrics</code></p>
  {/if}
</div>
