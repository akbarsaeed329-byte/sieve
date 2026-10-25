<script>
  import { onMount } from 'svelte';
  import { del, get, post } from '$lib/api.js';
  import { toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  let exc = $state([]), mw = $state([]);
  let x = $state({ rule_id: '', agent_name: '', srcip: '', user: '', reason: '', expires_in_days: 30 });
  const local = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  let m = $state({ agent_name: '', starts_at: local(new Date()), ends_at: local(new Date(Date.now() + 2 * 3600e3)), reason: '' });
  const load = async () => { [exc, mw] = await Promise.all([get('/api/exceptions'), get('/api/maintenance')]); };
  onMount(load);
  async function addExc(e) { e.preventDefault();
    const b = Object.fromEntries(Object.entries(x).map(([k, v]) => [k, v === '' ? null : v]));
    try { await post('/api/exceptions', { ...b, expires_in_days: Number(x.expires_in_days) }); toast('Exception added.'); x.reason = ''; load(); } catch (err) { toast(errText(err)); } }
  async function addMw(e) { e.preventDefault();
    try { await post('/api/maintenance', { ...m, starts_at: new Date(m.starts_at).toISOString(), ends_at: new Date(m.ends_at).toISOString() }); toast('Maintenance window added.'); load(); } catch (err) { toast(errText(err)); } }
  async function rm(path, msg) { try { await del(path); toast(msg); load(); } catch (err) { toast(errText(err)); } }
</script>
<section class="card pad stack" aria-labelledby="mw"><h2 id="mw">Maintenance windows</h2>
  <p class="muted small">During an approved window, alerts on that host are kept and labelled, and only critical incidents notify. A log line that merely <em>claims</em> maintenance changes nothing: only these records count.</p>
  <form class="grid" onsubmit={addMw}>
    <div class="field"><label for="m1">Host (agent name, or * for all)</label><input id="m1" type="text" required bind:value={m.agent_name} /></div>
    <div class="field"><label for="m2">Starts</label><input id="m2" type="datetime-local" required bind:value={m.starts_at} /></div>
    <div class="field"><label for="m3">Ends (max 7 days)</label><input id="m3" type="datetime-local" required bind:value={m.ends_at} /></div>
    <div class="field"><label for="m4">Reason</label><input id="m4" type="text" required minlength="3" bind:value={m.reason} placeholder="Patch Tuesday, change CHG-1042" /></div>
    <button class="btn primary">Add window</button></form>
  <div class="table-wrap"><table><thead><tr><th>Host</th><th>When</th><th>Reason</th><th>By</th><th>State</th><th></th></tr></thead><tbody>
    {#each mw as w}<tr><td class="mono">{w.agent_name}</td><td class="small">{new Date(w.starts_at).toLocaleString()} – {new Date(w.ends_at).toLocaleString()}</td><td>{w.reason}</td><td>{w.created_by}</td><td>{w.state}</td>
      <td>{#if w.state !== 'past'}<button class="btn small" onclick={() => rm(`/api/maintenance/${w.id}`, 'Window ended.')}>End now</button>{/if}</td></tr>
    {:else}<tr><td colspan="6" class="empty">No windows.</td></tr>{/each}</tbody></table></div>
</section>
<section class="card pad stack" aria-labelledby="ex"><h2 id="ex">Approved exceptions</h2>
  <p class="muted small">Matching alerts are suppressed with your reason and stay reviewable under Hidden alerts. Keep them narrow: a rule ID, or two of host, IP and user. Tripwire hits are never suppressed.</p>
  <form class="grid" onsubmit={addExc}>
    <div class="field"><label for="e1">Rule ID</label><input id="e1" type="text" bind:value={x.rule_id} /></div>
    <div class="field"><label for="e2">Host</label><input id="e2" type="text" bind:value={x.agent_name} /></div>
    <div class="field"><label for="e3">Source IP</label><input id="e3" type="text" bind:value={x.srcip} /></div>
    <div class="field"><label for="e4">User</label><input id="e4" type="text" bind:value={x.user} /></div>
    <div class="field"><label for="e5">Reason</label><input id="e5" type="text" required minlength="3" bind:value={x.reason} /></div>
    <div class="field"><label for="e6">Expires after (days)</label><input id="e6" type="number" min="1" max="365" bind:value={x.expires_in_days} /></div>
    <button class="btn primary">Add exception</button></form>
  <div class="table-wrap"><table><thead><tr><th>Scope</th><th>Reason</th><th>By</th><th class="num">Hits</th><th>Expires</th><th></th></tr></thead><tbody>
    {#each exc as e}<tr class:muted={!e.active}><td class="mono small">{[e.rule_id && `rule ${e.rule_id}`, e.agent_name, e.srcip, e.user].filter(Boolean).join(' · ')}</td><td>{e.reason}</td><td>{e.created_by}</td><td class="num">{e.hits}</td>
      <td class="small">{e.expired ? 'expired' : e.expires_at ? new Date(e.expires_at).toLocaleDateString() : 'never'}</td>
      <td>{#if e.active}<button class="btn small" onclick={() => rm(`/api/exceptions/${e.id}`, 'Exception removed.')}>Remove</button>{:else}<span class="small">inactive</span>{/if}</td></tr>
    {:else}<tr><td colspan="6" class="empty">No exceptions.</td></tr>{/each}</tbody></table></div>
</section>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; align-items: end; }</style>
