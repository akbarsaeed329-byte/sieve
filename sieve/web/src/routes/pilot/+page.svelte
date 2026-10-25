<script>
  // Prove it on your own data: before/after, agreement with your analysts, and an injection self-test.
  import { onMount } from 'svelte';
  import { get, post } from '$lib/api.js';
  import { app, toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  let r = $state(null), busy = $state(false);
  const load = async () => (r = await get('/api/pilot/report'));
  onMount(load);
  const pct = (x) => (x == null ? '–' : `${Math.round(x * 100)}%`);
  async function start() { if (!confirm('Restart the pilot period from now? Earlier data stays, but the report starts counting from today.')) return; await post('/api/pilot/start').catch((e) => toast(errText(e))); load(); }
  async function selftest() { busy = true; try { await post('/api/pilot/selftest?sample=150'); toast('Self-test finished.'); load(); } catch (e) { toast(errText(e)); } finally { busy = false; } }
</script>
<svelte:head><title>Pilot · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="row between noprint" style="align-items:flex-end"><div class="stack" style="gap:6px"><h1>Pilot report</h1>
    <p class="muted">Gartner's advice for AI SOC tools: baseline your own operations, pilot rigorously, verify claims. This page does that on your data.</p></div>
    <div class="row">{#if app.me?.role === 'admin' && !app.me?.tenant_id}<button class="btn" onclick={start}>Restart pilot period</button>
      <button class="btn" disabled={busy} onclick={selftest}>{busy ? 'Testing…' : 'Run injection self-test'}</button>{/if}
      <button class="btn primary" onclick={() => window.print()}>Print / PDF</button></div></header>
  {#if r}
    <section class="card pad stack"><h2>Since {new Date(r.since).toLocaleDateString()} ({r.days} days)</h2>
      {#each r.verdict as v}<p style="font-size:16px">{v}</p>{/each}
      <div class="kpis card">
        <div class="kpi"><span class="small muted">Raw Wazuh would have paged</span><span class="v">{r.period.raw_would_page.toLocaleString()}</span></div>
        <div class="kpi"><span class="small muted">Sieve notified</span><span class="v">{r.period.sieve_notified.toLocaleString()}</span></div>
        <div class="kpi"><span class="small muted">Noise reduction</span><span class="v">{pct(r.noise_reduction)}</span></div>
        <div class="kpi"><span class="small muted">Analyst hours saved (estimate)</span><span class="v">{r.hours_saved_estimate}</span></div></div>
      <p class="small muted">Estimate assumes {r.assumption}.</p>
      <div class="kpis card">
        <div class="kpi"><span class="small muted">Agreement with your analysts</span><span class="v">{pct(r.period.agreement)}</span><span class="small muted">{r.period.labelled} labelled</span></div>
        <div class="kpi"><span class="small muted">Rated lower than a human</span><span class="v">{r.period.under_called}</span></div>
        <div class="kpi"><span class="small muted">Median time to acknowledge</span><span class="v">{r.period.median_tta_min ?? '–'} min</span></div>
        <div class="kpi"><span class="small muted">False-positive rate</span><span class="v">{pct(r.period.false_positive_rate)}</span></div></div>
    </section>
    <section class="card pad stack"><h2>Injection self-test</h2>
      {#if r.injection_selftest}{@const t = r.injection_selftest}
        <p style="font-size:16px">{t.poisoned_copies} poisoned copies of {t.incidents_tested} of your own incidents (four attack classes). <strong>{t.bands_changed === 0 ? 'No severity changed.' : `${t.bands_changed} severities changed: investigate.`}</strong></p>
        <div class="table-wrap"><table><thead><tr><th>Attack class</th><th class="num">Caught by the tripwire</th></tr></thead><tbody>
          {#each Object.entries(t.tripwire_by_class) as [k, v]}<tr><td>{k}</td><td class="num">{pct(v)}</td></tr>{/each}</tbody></table></div>
        <p class="small">False alarms on the clean originals: {pct(t.tripwire_false_alarm_on_clean)} · Hijacked-model sentences blocked by validation: {t.hijacked_model_sentences_blocked} of 2 · run {new Date(t.at).toLocaleString()}</p>
        <p class="small muted">{t.note}</p>
      {:else}<p class="muted">Not run yet. An admin can run it above; it takes a few seconds and changes nothing.</p>{/if}
    </section>
  {/if}
</div>
<style>@media print { :global(nav), .noprint { display: none !important; } }</style>
