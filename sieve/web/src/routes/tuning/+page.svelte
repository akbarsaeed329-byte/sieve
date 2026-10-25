<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  import { post, put } from '$lib/api.js';
  import { app, toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  let rows = $state([]), exc = $state([]), days = $state(30), ac = $state(null), wt = $state(null);
  const load = async () => { [rows, exc, ac, wt] = await Promise.all([get(`/api/tuning/noisy-rules?days=${days}`), get('/api/exceptions'),
    get('/api/autoclose/candidates'), get('/api/tuning/weights')]); };
  async function approve(rule, on) {
    const list = on ? [...new Set([...ac.rules.filter((r) => r.approved).map((r) => r.rule_id), rule])] : ac.rules.filter((r) => r.approved && r.rule_id !== rule).map((r) => r.rule_id);
    try { await put('/api/settings', { autoclose: { rules: list } }); toast(on ? `Rule ${rule} may auto-close while it keeps its record.` : `Auto-close off for rule ${rule}.`); load(); } catch (e) { toast(errText(e)); } }
  async function acEnable(on) { try { await put('/api/settings', { autoclose: { enabled: on } }); load(); } catch (e) { toast(errText(e)); } }
  async function applyW() { try { await post('/api/tuning/weights/apply'); toast('New weights applied and recorded in the audit log.'); load(); } catch (e) { toast(errText(e)); } }
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
  {#if wt}<section class="card pad stack" aria-labelledby="wt"><h2 id="wt">Score weights from your verdicts</h2>
    {#if !wt.enough_data}<p class="muted">{wt.message} ({wt.labelled} so far)</p>
    {:else}<p>{wt.message}</p>
      <div class="kpis card"><div class="kpi"><span class="small muted">Real incidents notified</span><span class="v">{wt.current.true_positives_notified} → {wt.proposed.true_positives_notified}</span></div>
        <div class="kpi"><span class="small muted">False positives notified</span><span class="v">{wt.current.false_positives_notified} → {wt.proposed.false_positives_notified}</span></div></div>
      {#if Object.keys(wt.changes).length}<p class="small">{Object.entries(wt.changes).map(([k, v]) => `${k}: ${v.from} → ${v.to}`).join(' · ')}</p>
        {#if app.me?.role === 'admin'}<button class="btn primary" style="align-self:flex-start" onclick={applyW}>Apply these weights</button>{/if}{/if}{/if}
    <p class="small muted">Based on {wt.labelled} closed incidents without overrides. A change is only proposed if no real incident would lose its notification.</p></section>{/if}
  {#if ac}<section class="card pad stack" aria-labelledby="ac"><div class="row between"><h2 id="ac">Auto-close (earned)</h2>
      {#if app.me?.role === 'admin'}<label class="row"><input type="checkbox" checked={ac.enabled} onchange={(e) => acEnable(e.currentTarget.checked)} /> Enabled</label>{/if}</div>
    <p class="muted small">A rule can auto-close {ac.max_band} and lower incidents only after analysts closed at least {ac.min_verdicts} of its incidents with {Math.round(ac.min_agreement * 100)}% agreeing they were false positives, and only while it keeps that record. Tripwire, override and correlation incidents are never auto-closed. Auto-closed items stay reviewable, and reopening one revokes the rule.</p>
    <div class="table-wrap"><table><thead><tr><th>Rule</th><th class="num">Verdicts</th><th class="num">Agreement</th><th>Eligible</th><th>Approved</th></tr></thead><tbody>
      {#each ac.rules as r}<tr><td><span class="mono">{r.rule_id}</span> <span class="small muted">{r.title}</span></td><td class="num">{r.verdicts}</td><td class="num">{Math.round(r.agreement * 100)}%</td>
        <td>{r.eligible ? 'yes' : 'not yet'}</td><td><input type="checkbox" aria-label="Approve auto-close for rule {r.rule_id}" checked={r.approved} disabled={app.me?.role !== 'admin' || (!r.eligible && !r.approved)} onchange={(e) => approve(r.rule_id, e.currentTarget.checked)} /></td></tr>
      {:else}<tr><td colspan="5" class="empty">No verdicts yet.</td></tr>{/each}</tbody></table></div>
    {#if ac.recently_auto_closed.length}<h3>Recently auto-closed</h3><ul>{#each ac.recently_auto_closed as i}<li><a href="/incidents/{i.id}">#{i.id} {i.title}</a> on {i.agent_name}</li>{/each}</ul>{/if}
  </section>{/if}
  <section class="stack" aria-labelledby="ex"><div class="row between"><h2 id="ex">Approved exceptions</h2><a href="/settings/exceptions">Manage</a></div>
    <div class="card table-wrap"><table><thead><tr><th>Scope</th><th>Reason</th><th>By</th><th class="num">Hits</th><th>Expires</th></tr></thead>
      <tbody>{#each exc.filter((x) => x.active) as x}<tr><td class="mono small">{[x.rule_id && `rule ${x.rule_id}`, x.agent_name, x.srcip, x.user].filter(Boolean).join(' · ')}</td>
        <td>{x.reason}{#if x.from_incident} <a class="small" href="/incidents/{x.from_incident}">from #{x.from_incident}</a>{/if}</td><td>{x.created_by}</td><td class="num">{x.hits}</td>
        <td class="small">{x.expires_at ? new Date(x.expires_at).toLocaleDateString() : 'never'}</td></tr>
      {:else}<tr><td colspan="5" class="empty">No active exceptions.</td></tr>{/each}</tbody></table></div></section>
</div>
