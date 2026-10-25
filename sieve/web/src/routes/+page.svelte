<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  import { app, tq } from '$lib/state.svelte.js';
  import { ago, fmt, plural } from '$lib/util.js';
  import Pill from '$c/Pill.svelte';
  import Queue from '$c/Queue.svelte';
  import ErrorBox from '$c/ErrorBox.svelte';

  let st = $state(null), q = $state([]), hidden = $state(null), error = $state(null), search = $state('');
  async function load() {
    try {
      [st, q, hidden] = await Promise.all([get(`/api/stats${tq('?')}`), get(`/api/incidents?status=all&limit=50${tq()}${search ? '&q=' + encodeURIComponent(search) : ''}`).then((r) => r.items),
        get('/api/suppressions?sampled=true')]);
      error = null;
    } catch (e) { error = e; }
  }
  onMount(() => { const t = setInterval(load, 10000); return () => clearInterval(t); });
  $effect(() => { app.tenant; load(); });
  const hour = new Date().getHours();
  const hello = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
  let reviewed = $derived(hidden ? hidden.items.filter((x) => x.outcome).length : 0);
</script>

<svelte:head><title>Overview · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="row between" style="align-items:flex-end">
    <div class="stack" style="gap:6px"><h1>{hello}, {app.me?.username}</h1>
      <p class="muted" style="font-size:15px">{#if st}{st.needs_you.length ? `${st.needs_you.length === 1 ? 'One thing needs' : `${st.needs_you.length} things need`} you.` : 'Nothing needs you right now.'} Everything else is handled or waiting in the queue.{/if}</p></div>
    <div class="field" style="flex:0 1 320px;min-width:220px"><label for="search">Search</label>
      <input id="search" type="search" placeholder="Incidents, hosts or IPs" bind:value={search} oninput={load} /></div>
  </header>
  <ErrorBox {error} />
  {#if st?.shadow_mode}<div class="banner info" role="note">Shadow mode is on: Sieve triages and records everything but sends no notifications. Compare its bands with yours under Metrics.</div>{/if}
  {#if st?.channel_failures_last_hour}<div class="banner bad" role="alert">A notification channel failed {plural(st.channel_failures_last_hour, 'time')} in the last hour. <a href="/health">Open Health</a></div>{/if}

  <section aria-labelledby="needs" class="stack">
    <h2 id="needs">Needs you now</h2>
    <div class="card">
      {#each st?.needs_you || [] as i, n (i.id)}
        <div class="need" class:first={n === 0}>
          {#if i.tripwire && i.band !== 'critical'}<span class="tpill">Tripwire</span>{:else}<Pill band={i.band} />{/if}
          <div class="grow stack" style="gap:4px;flex:1 1 320px">
            <span style="font-size:16px;font-weight:600">{i.title} on {i.agent_name}</span>
            <span class="muted">{fmt(i.alert_count)} alert{i.alert_count === 1 ? '' : 's'} grouped into one incident, opened {ago(i.opened_at)} ago. Nobody has acknowledged it yet.
              {#if i.tripwire}A log field tried to steer the AI; Sieve treated it as data and kept the rule-based severity.{/if}</span>
          </div>
          <a class="btn {n === 0 ? 'primary' : ''}" href="/incidents/{i.id}">Open incident</a>
        </div>
      {:else}<div class="empty">Nothing needs you right now.</div>{/each}
    </div>
  </section>

  <section aria-labelledby="day" class="stack">
    <h2 id="day">Last 24 hours</h2>
    <div class="card kpis">
      <div class="kpi"><span class="small muted">Alerts received from Wazuh</span><span class="v">{fmt(st?.alerts_received)}</span></div>
      <div class="kpi"><span class="small muted">Notifications sent to you</span><span class="v">{fmt(st?.notifications)}</span></div>
      <div class="kpi"><span class="small muted">Suppressed, each with a reason</span><span class="v">{fmt(st?.suppressed)}</span><a class="small" href="/hidden">See why</a></div>
      <div class="kpi"><span class="small muted">Median time to acknowledge</span><span class="v">{st?.median_tta_min == null ? '–' : `${Math.round(st.median_tta_min)} min`}</span></div>
    </div>
  </section>

  <div class="row" style="align-items:flex-start;gap:24px">
    <section aria-labelledby="queue" class="stack" style="flex:999 1 600px;min-width:0">
      <div class="row between"><h2 id="queue">Incident queue</h2><span class="small muted">Open first, sorted by severity, then age</span></div>
      <Queue items={q} onchange={load} />
    </section>
    <aside aria-labelledby="audit-h" class="card pad stack" style="flex:1 1 280px">
      <h2 id="audit-h" style="font-size:16px">Check what was hidden</h2>
      <p style="color:var(--soft)">Each week Sieve picks 20 suppressed alerts at random. Confirm they were noise, or bring any back. A filter that hid a real attack gets flagged.</p>
      {#if hidden}
        <div class="small stack" style="gap:6px">
          <div class="row between"><span class="muted">This week's sample</span><span>{reviewed} of {hidden.items.length} checked</span></div>
          <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax={hidden.items.length} aria-valuenow={reviewed} aria-label="Review progress"><i style="width:{hidden.items.length ? (100 * reviewed) / hidden.items.length : 0}%"></i></div>
          <div class="row between"><span class="muted">Last week</span><span>{hidden.last_week_restored} alert{hidden.last_week_restored === 1 ? '' : 's'} restored</span></div>
        </div>
      {/if}
      <a class="btn" href="/hidden">Start review</a>
    </aside>
  </div>
</div>
<style>
  .need { display: flex; flex-wrap: wrap; gap: 16px; align-items: center; padding: 18px 20px; border-top: 1px solid var(--line-2); }
  .need.first { border-top: none; }
  .tpill { padding: 4px 10px; border-radius: 999px; background: var(--amber-bg); border: 1px dashed var(--amber); color: var(--amber-text); font-size: 13px; font-weight: 600; }
  .bar { height: 6px; border-radius: 999px; background: var(--line-2); overflow: hidden; }
  .bar i { display: block; height: 100%; background: var(--brand); }
</style>
