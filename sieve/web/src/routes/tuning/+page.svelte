<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  let rows = $state([]), exc = $state([]), days = $state(30);
  const load = async () => { [rows, exc] = await Promise.all([get(`/api/tuning/noisy-rules?days=${days}`), get('/api/exceptions')]); };
  onMount(load);
</script>
<svelte:head><title>Tuning · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="row between" style="align-items:flex-end"><div class="stack" style="gap:6px"><h1>Tuning</h1>
    <p class="muted">Your verdicts tune detection. Rules that keep producing false positives rise to the top, with a suggested fix.</p></div>
    <div class="field"><label for="d">Period</label><select id="d" bind:value={days} onchange={load}><option value={7}>7 days</option><option value={30}>30 days</option><option value={90}>90 days</option></select></div></header>
  <section class="stack" aria-labelledby="nr"><h2 id="nr">Rules by false-positive rate</h2>
    <div class="card table-wrap"><table><thead><tr><th>Rule</th><th class="num">Alerts</th><th class="num">Suppressed</th><th class="num">False positives</th><th class="num">Confirmed</th><th>Suggestion</th></tr></thead>
      <tbody>{#each rows as r}<tr><td><span class="mono">{r.rule_id}</span><br /><span class="small muted">{r.description}</span></td>
        <td class="num">{r.alerts}</td><td class="num">{r.suppressed}</td><td class="num">{r.false_positives}{#if r.fp_rate !== null} <span class="small muted">({Math.round(r.fp_rate * 100)}%)</span>{/if}</td>
        <td class="num">{r.confirmed}</td><td class="small">{r.suggestion || '–'}</td></tr>
      {:else}<tr><td colspan="6" class="empty">No data yet.</td></tr>{/each}</tbody></table></div></section>
  <section class="stack" aria-labelledby="ex"><div class="row between"><h2 id="ex">Approved exceptions</h2><a href="/settings/exceptions">Manage</a></div>
    <div class="card table-wrap"><table><thead><tr><th>Scope</th><th>Reason</th><th>By</th><th class="num">Hits</th><th>Expires</th></tr></thead>
      <tbody>{#each exc.filter((x) => x.active) as x}<tr><td class="mono small">{[x.rule_id && `rule ${x.rule_id}`, x.agent_name, x.srcip, x.user].filter(Boolean).join(' · ')}</td>
        <td>{x.reason}{#if x.from_incident} <a class="small" href="/incidents/{x.from_incident}">from #{x.from_incident}</a>{/if}</td><td>{x.created_by}</td><td class="num">{x.hits}</td>
        <td class="small">{x.expires_at ? new Date(x.expires_at).toLocaleDateString() : 'never'}</td></tr>
      {:else}<tr><td colspan="5" class="empty">No active exceptions.</td></tr>{/each}</tbody></table></div></section>
</div>
