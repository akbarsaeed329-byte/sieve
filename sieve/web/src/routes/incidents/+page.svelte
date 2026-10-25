<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  import Queue from '$c/Queue.svelte';
  import ErrorBox from '$c/ErrorBox.svelte';
  let status = $state('open'), band = $state(''), q = $state(''), data = $state({ items: [], total: 0 }), error = $state(null);
  async function load() {
    const p = new URLSearchParams({ status, limit: '200' });
    if (band) p.set('band', band);
    if (q) p.set('q', q);
    try { data = await get('/api/incidents?' + p); error = null; } catch (e) { error = e; }
  }
  onMount(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); });
</script>
<svelte:head><title>Incidents · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="stack" style="gap:6px"><h1>Incidents</h1><p class="muted">{data.total} incident{data.total === 1 ? '' : 's'} match.</p></header>
  <div class="row">
    <div class="field"><label for="st">Status</label><select id="st" bind:value={status} onchange={load}>
      <option value="open">Open</option><option value="new">New</option><option value="acknowledged">Acknowledged</option>
      <option value="resolved">Resolved</option><option value="false_positive">False positive</option><option value="all">All</option></select></div>
    <div class="field"><label for="bd">Severity</label><select id="bd" bind:value={band} onchange={load}>
      <option value="">Any</option><option value="critical">Critical</option><option value="high">High</option>
      <option value="medium">Medium</option><option value="low">Low</option></select></div>
    <div class="field grow" style="max-width:360px"><label for="q">Search</label><input id="q" type="search" placeholder="Title, host, IP or user" bind:value={q} oninput={load} /></div>
  </div>
  <ErrorBox {error} />
  <Queue items={data.items} onchange={load} />
</div>
