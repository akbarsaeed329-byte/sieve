<script>
  import { onMount } from 'svelte';
  import { del, get, post } from '$lib/api.js';
  import { toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  let rules = $state([]), dry = $state(null), incId = $state('');
  const blank = () => ({ name: '', trigger: 'incident.created', min_band: '', hosts: '', rule_ids: '', techniques: '', tripwire: false, actions: [{ type: 'assign', user: '' }] });
  let r = $state(blank());
  const L = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const load = async () => { try { rules = await get('/api/automation-rules'); } catch { /* access denied or offline: keep the page usable */ } };
  onMount(load);
  const body = () => {
    const c = {}; if (r.min_band) c.min_band = r.min_band; if (L(r.hosts).length) c.hosts = L(r.hosts); if (L(r.rule_ids).length) c.rule_ids = L(r.rule_ids);
    if (L(r.techniques).length) c.techniques = L(r.techniques); if (r.tripwire) c.tripwire = true;
    const actions = r.actions.map((a) => a.type === 'tag' ? { type: 'tag', tags: L(a.tags || '') } : { ...a });
    return { name: r.name, trigger: r.trigger, conditions: c, actions };
  };
  async function save(e) { e.preventDefault(); try { await post('/api/automation-rules', body()); toast('Workflow saved.'); r = blank(); dry = null; load(); } catch (err) { toast(errText(err)); } }
  async function test() { try { dry = await post(`/api/automation-rules/dry-run?incident_id=${Number(incId)}`, body()); } catch (err) { toast(errText(err)); } }
  const LABEL = { assign: 'Assign to', tag: 'Add tags', team: 'Set team', notify: 'Notify channel', page_oncall: 'Page on-call', webhook: 'Call webhook', jira: 'Open Jira issue' };
</script>
<section class="card pad stack" aria-labelledby="wf"><h2 id="wf">New workflow</h2>
  <p class="muted small">"When this happens, and these match, do that." Actions assign, tag, notify, page or open tickets. Nothing here ever runs on a host: response stays a human decision.</p>
  <form class="stack" onsubmit={save}>
    <div class="grid">
      <div class="field"><label for="n">Name</label><input id="n" type="text" required minlength="3" bind:value={r.name} placeholder="Critical on PCI hosts → page on-call" /></div>
      <div class="field"><label for="tr">When</label><select id="tr" bind:value={r.trigger}><option value="incident.created">An incident is created</option><option value="incident.band_raised">Severity rises</option><option value="incident.tripwire">A tripwire fires</option><option value="incident.overdue">An SLA is missed</option></select></div>
      <div class="field"><label for="mb">and severity is at least</label><select id="mb" bind:value={r.min_band}><option value="">any</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select></div>
      <div class="field"><label for="h">hosts match</label><input id="h" type="text" bind:value={r.hosts} placeholder="web-*, pci-*" /></div>
      <div class="field"><label for="ri">rule IDs</label><input id="ri" type="text" bind:value={r.rule_ids} /></div>
      <div class="field"><label for="te">ATT&amp;CK techniques</label><input id="te" type="text" bind:value={r.techniques} placeholder="T1110" /></div>
    </div>
    <label class="row small"><input type="checkbox" bind:checked={r.tripwire} /> only when a tripwire fired</label>
    <h3>Then</h3>
    {#each r.actions as a, k}<div class="row act">
      <select aria-label="Action" bind:value={a.type}>{#each Object.entries(LABEL) as [v, l]}<option value={v}>{l}</option>{/each}</select>
      {#if a.type === 'assign'}<input type="text" aria-label="Username" placeholder="username" bind:value={a.user} />
      {:else if a.type === 'tag'}<input type="text" aria-label="Tags" placeholder="pci, urgent" bind:value={a.tags} />
      {:else if a.type === 'team'}<input type="text" aria-label="Team" bind:value={a.team} />
      {:else if a.type === 'notify'}<select aria-label="Channel" bind:value={a.channel}><option value="">all channels</option><option value="telegram">Telegram</option><option value="slack">Slack</option><option value="teams">Teams</option><option value="email">Email</option></select>
      {:else if a.type === 'webhook'}<input type="url" aria-label="Webhook URL" placeholder="https://" bind:value={a.url} />{/if}
      <button type="button" class="btn small danger" onclick={() => (r.actions = r.actions.filter((x) => x !== a))}>✕</button></div>{/each}
    <button type="button" class="btn small" style="align-self:flex-start" onclick={() => (r.actions = [...r.actions, { type: 'tag', tags: '' }])}>Add action</button>
    <div class="row"><div class="field"><label for="di">Try on incident #</label><input id="di" type="number" min="1" bind:value={incId} style="max-width:120px" /></div>
      <button type="button" class="btn" style="align-self:flex-end" onclick={test} disabled={!incId}>Dry run</button>
      {#if dry}<span class="small {dry.would_match ? 'ok-text' : 'muted'}" style="align-self:center">{dry.would_match ? `Would run: ${dry.actions.join(', ')}` : 'Would not match'}</span>{/if}</div>
    <button class="btn primary" style="align-self:flex-start">Save workflow</button>
  </form>
</section>
<div class="card table-wrap"><table><thead><tr><th>Workflow</th><th>When</th><th>Then</th><th class="num">Runs</th><th></th></tr></thead><tbody>
  {#each rules as x}<tr class:muted={!x.enabled}><td>{x.name}<br /><span class="small muted mono">{JSON.stringify(x.conditions)}</span></td><td>{x.trigger.replace('incident.', '')}</td>
    <td class="small">{x.actions.map((a) => LABEL[a.type] || a.type).join(', ')}</td><td class="num">{x.runs}</td>
    <td>{#if x.enabled}<button class="btn small" onclick={async () => { await del(`/api/automation-rules/${x.id}`).catch((e) => toast(errText(e))); load(); }}>Disable</button>{/if}</td></tr>
  {:else}<tr><td colspan="5" class="empty">No workflows yet.</td></tr>{/each}</tbody></table></div>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; align-items: end; }
  .act select, .act input { max-width: 260px; }</style>
