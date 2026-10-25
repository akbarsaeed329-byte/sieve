<script>
  // Executive report (plain words for owners and CFOs) and shift handover. Print-friendly.
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  import { BAND } from '$lib/util.js';
  import { page } from '$app/state';
  import { app } from '$lib/state.svelte.js';
  import Pill from '$c/Pill.svelte';
  let e = $state(null), h = $state(null), days = $state(7), tab = $state('exec');
  const load = async () => { try { const t = page.url.searchParams.get('tenant') || (app.me?.tenant_id ? '' : app.tenant); [e, h] = await Promise.all([get(`/api/reports/executive?days=${days}${t ? '&tenant=' + t : ''}`), get('/api/reports/handover?hours=12')]); } catch { /* keep the page usable */ } };
  onMount(load);
  const v = (x, suf = '') => (x === null || x === undefined ? '–' : `${x}${suf}`);
</script>
<svelte:head><title>Reports · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="row between noprint" style="align-items:flex-end"><div class="stack" style="gap:6px"><h1>Reports</h1>
    <p class="muted">For managers and for the next shift. Use Print to save as PDF.</p></div>
    <div class="row"><div class="seg2" role="tablist">
      <button role="tab" aria-selected={tab === 'exec'} onclick={() => (tab = 'exec')}>Executive</button>
      <button role="tab" aria-selected={tab === 'hand'} onclick={() => (tab = 'hand')}>Shift handover</button></div>
      {#if tab === 'exec'}<select aria-label="Period" bind:value={days} onchange={load}><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option></select>{/if}
      <button class="btn" onclick={() => window.print()}>Print / save PDF</button></div></header>
  {#if tab === 'exec' && e}
    <section class="card pad stack">
      {#if e.brand?.name}<div class="brandbar" style="border-color:{e.brand.color || 'var(--brand)'}"><strong>{e.brand.title || e.brand.name}</strong></div>{/if}
      <h2>Security summary, last {e.days} days</h2>
      <p style="font-size:16px">Your systems produced <strong>{e.alerts.toLocaleString()}</strong> security alerts. Sieve handled
        {v(e.noise_reduction_pct, '%')} of them automatically and raised <strong>{e.notified_incidents}</strong> to people.
        {#if e.manipulation_attempts}It also caught <strong>{e.manipulation_attempts}</strong> {e.manipulation_attempts === 1 ? 'attempt' : 'attempts'} to trick the AI.{/if}
        {e.open_now ? (e.open_now === 1 ? 'One item is still open.' : `${e.open_now} items are still open.`) : 'Nothing is waiting.'}</p>
      <div class="kpis card"><div class="kpi"><span class="small muted">Incidents</span><span class="v">{e.incidents}</span></div>
        <div class="kpi"><span class="small muted">Median time to acknowledge</span><span class="v">{v(e.median_ack_min, ' min')}</span></div>
        <div class="kpi"><span class="small muted">Median time to resolve</span><span class="v">{v(e.median_resolve_h, ' h')}</span></div>
        <div class="kpi"><span class="small muted">Acknowledged within SLA</span><span class="v">{v(e.sla_met_pct, '%')}</span></div>
        <div class="kpi"><span class="small muted">False positives</span><span class="v">{v(e.false_positive_pct, '%')}</span></div></div>
      <div class="row" style="align-items:flex-start;gap:32px">
        <div class="stack"><h3>By severity</h3>{#each ['critical', 'high', 'medium', 'low'] as b}<span class="row"><Pill band={b} small /> {e.by_band[b] || 0}</span>{/each}</div>
        <div class="stack"><h3>Most targeted systems</h3>{#each e.top_hosts as [host, n]}<span><span class="mono">{host}</span> · {n}</span>{:else}<span class="muted">none</span>{/each}</div>
        <div class="stack"><h3>Most seen attack techniques</h3>{#each e.top_techniques as [t, n]}<span><a href="https://attack.mitre.org/techniques/{t.replace('.', '/')}/">{t}</a> · {n}</span>{:else}<span class="muted">none</span>{/each}</div>
      </div>
    </section>
  {:else if tab === 'hand' && h}
    <section class="card pad stack"><h2>Shift handover</h2>
      {#if h.overdue.length}<div class="banner bad">{h.overdue.length === 1 ? 'One incident is' : `${h.overdue.length} incidents are`} past the SLA and not acknowledged.</div>{/if}
      <h3>Open now ({h.open.length})</h3>
      <div class="table-wrap"><table><tbody>{#each h.open as i}<tr><td><Pill band={i.band} small /></td><td><a href="/incidents/{i.id}">{i.ref} {i.title}</a></td><td class="mono">{i.agent_name}</td><td>{i.assignee || 'Unassigned'}</td></tr>{:else}<tr><td class="empty">Nothing open.</td></tr>{/each}</tbody></table></div>
      <h3>Closed in the last {h.hours} h ({h.closed.length})</h3>
      <ul>{#each h.closed as i}<li><a href="/incidents/{i.id}">{i.ref} {i.title}</a> · {i.status.replace('_', ' ')}</li>{:else}<li class="muted">None.</li>{/each}</ul>
      <h3>Notes from the shift</h3>
      <ul>{#each h.notes as n}<li><a href="/incidents/{n.incident_id}">#{n.incident_id}</a> {n.author}: {n.body}</li>{:else}<li class="muted">No notes.</li>{/each}</ul>
    </section>
  {/if}
</div>
<style>
  .brandbar { border-left: 6px solid; padding: 6px 12px; font-size: 18px; }
  .seg2 { display: flex; border: 1px solid var(--input); border-radius: 8px; overflow: hidden; }
  .seg2 button { min-height: 44px; padding: 0 14px; border: none; background: var(--card); color: var(--ink); cursor: pointer; font: 500 14px var(--sans); }
  .seg2 button[aria-selected=true] { background: var(--ink); color: var(--ground); }
  @media print { :global(nav), .noprint { display: none !important; } :global(main) { padding: 0 !important; } }
</style>
