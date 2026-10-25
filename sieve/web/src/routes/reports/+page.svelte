<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  import Chart from '$c/Chart.svelte';
  import ErrorBox from '$c/ErrorBox.svelte';
  let m = $state(null), sh = $state(null), days = $state(14), error = $state(null);
  async function load() {
    try { [m, sh] = await Promise.all([get(`/api/metrics/summary?days=${days}`), get('/api/shadow/agreement')]); }
    catch (e) { error = e; }
  }
  onMount(load);
  const C = { a: '#56625F', b: '#0B6E69', crit: '#8F1C13', high: '#C2621A', med: '#B39200', low: '#1F4677' };
  const pct = (x) => (x == null ? '–' : `${Math.round(x * 100)}%`);
</script>
<svelte:head><title>Metrics · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="row between" style="align-items:flex-end"><div class="stack" style="gap:6px"><h1>Metrics</h1>
    <p class="muted">Is Sieve reducing noise without hiding attacks?</p></div>
    <div class="field"><label for="d">Period</label><select id="d" bind:value={days} onchange={load}><option value={7}>7 days</option><option value={14}>14 days</option><option value={30}>30 days</option><option value={90}>90 days</option></select></div></header>
  <ErrorBox {error} />
  {#if m}
    <div class="grid">
      <Chart title="Alerts in vs notifications out" labels={m.days} series={[{ name: 'Alerts in', color: C.a, values: m.alerts_in }, { name: 'Notifications out', color: C.b, values: m.notifications_out }]} />
      <Chart title="Incidents by severity" kind="bar" stacked labels={m.days} series={[{ name: 'Critical', color: C.crit, values: m.incidents_by_band.critical }, { name: 'High', color: C.high, values: m.incidents_by_band.high }, { name: 'Medium', color: C.med, values: m.incidents_by_band.medium }, { name: 'Low', color: C.low, values: m.incidents_by_band.low }]} />
      <Chart title="AI calls per day" kind="bar" labels={m.days} series={[{ name: 'LLM calls', color: C.b, values: m.llm_calls }]} />
      <Chart title="Suppression rate" unit="%" labels={m.days} series={[{ name: 'Suppressed %', color: C.a, values: m.suppression_rate }]} />
    </div>
    <p class="small muted">Time to first notification: p50 {m.first_notify_ms.p50 ?? '–'} ms, p95 {m.first_notify_ms.p95 ?? '–'} ms (target p95 under 1,000 ms).</p>
  {/if}
  {#if sh}
    <section class="card pad stack" aria-labelledby="sh"><h2 id="sh">Shadow-mode agreement</h2>
      <p class="muted">Before trusting Sieve on a new network, label incidents with the band you would have chosen (on each incident page or via the API) and compare.</p>
      <div class="kpis"><div class="kpi"><span class="small muted">Labelled</span><span class="v">{sh.labelled} / {sh.incidents}</span></div>
        <div class="kpi"><span class="small muted">Exact agreement</span><span class="v">{pct(sh.agreement)}</span></div>
        <div class="kpi"><span class="small muted">Within one band</span><span class="v">{pct(sh.within_one_band)}</span></div>
        <div class="kpi"><span class="small muted">Cohen's kappa</span><span class="v">{sh.cohen_kappa ?? '–'}</span></div></div>
      {#if sh.sieve_lower_than_human.length}<p class="error">Sieve rated {sh.sieve_lower_than_human.length} incident(s) lower than a human did: {#each sh.sieve_lower_than_human as id}<a href="/incidents/{id}">#{id}</a> {/each}</p>{/if}
    </section>
  {/if}
</div>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 24px; }</style>
