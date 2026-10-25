<script>
  // Training mode: blind verdicts on real, closed incidents, then the senior resolution is revealed.
  import { onMount } from 'svelte';
  import { get, post } from '$lib/api.js';
  import { errText } from '$lib/util.js';
  import { toast } from '$lib/state.svelte.js';
  import Pill from '$c/Pill.svelte';
  let c = $state(null), verdict = $state('real'), band = $state('high'), res = $state(null);
  const next = async () => { res = null; c = await get('/api/practice/next'); };
  onMount(next);
  async function submit(e) { e.preventDefault(); try { res = await post(`/api/practice/${c.id}`, { verdict, band }); } catch (err) { toast(errText(err)); } }
</script>
<svelte:head><title>Practice · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="stack" style="gap:6px"><h1>Practice</h1><p class="muted">Real incidents your team already closed, without the answer. Decide, then compare with what actually happened. Automation clears the easy alerts; this keeps the hard ones teaching people.</p></header>
  {#if c?.done}<p class="muted">You have practised every closed incident. New ones appear as your team closes them.</p>
  {:else if c}
    <section class="card pad stack"><h2>{c.title}</h2>
      <p class="small">Host <span class="mono">{c.host}</span> · source <span class="mono">{c.srcip || '–'}</span> · user <span class="mono">{c.user || '–'}</span> · {c.alert_count} alerts {c.tripwire ? '· a field contained instruction-like text' : ''}</p>
      <details open><summary class="small">Log lines</summary>{#each c.alerts.slice(0, 12) as a}<pre class="log" style="margin-top:6px">{new Date(a.time).toLocaleTimeString()} rule {a.rule_id} (level {a.level})  {a.full_log}</pre>{/each}</details>
      {#if !res}
        <form class="row" onsubmit={submit}>
          <div class="field"><label for="v">Your verdict</label><select id="v" bind:value={verdict}><option value="real">Real incident</option><option value="false_positive">False positive</option></select></div>
          <div class="field"><label for="b">Severity</label><select id="b" bind:value={band}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
          <button class="btn primary" style="align-self:flex-end">Reveal</button></form>
      {:else}
        <div class="banner {res.correct_verdict ? 'info' : 'bad'} stack"><strong>{res.correct_verdict ? 'Right call.' : 'Not quite.'} The team closed it as {res.actual_verdict === 'real' ? 'a real incident' : 'a false positive'}, <Pill band={res.actual_band} small />.</strong>
          {#each res.overrides as o}<span class="small">{o}</span>{/each}
          {#each res.notes as n}<span class="small">{n.author}: {n.body}</span>{/each}</div>
        <p class="small muted">Your record: {res.stats.attempts} tried · verdicts {Math.round(res.stats.verdict_accuracy * 100)}% · severity {Math.round(res.stats.band_accuracy * 100)}%</p>
        <button class="btn" style="align-self:flex-start" onclick={next}>Next case</button>
      {/if}
    </section>
  {/if}
</div>
