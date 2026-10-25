<script>
  import { S, save } from '$lib/settings.svelte.js';
  let routes = $state(JSON.parse(JSON.stringify(S.s.routes || [])));
  let assets = $state(JSON.parse(JSON.stringify(S.s.assets || [])));
  const L = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const add = () => (routes = [...routes, { name: 'web-team', hosts: ['web-*'], tags: [], min_band: 'high', team: 'Web team', telegram_chat_id: '', slack_channel: '', email_to: [], assign_to: '', exclusive: false, enabled: true }]);
</script>
<section class="card pad stack" aria-labelledby="rt"><h2 id="rt">Team routing</h2>
  <p class="muted small">Send incidents on some hosts to a team's own chat, channel or inbox, and assign an owner automatically. Match by host pattern (<code>web-*</code>) or asset tag.</p>
  {#each routes as r, k}
    <div class="grid route">
      <div class="field"><label for="n{k}">Name</label><input id="n{k}" type="text" bind:value={r.name} /></div>
      <div class="field"><label for="h{k}">Hosts (patterns)</label><input id="h{k}" type="text" value={r.hosts.join(', ')} onchange={(e) => (r.hosts = L(e.currentTarget.value))} /></div>
      <div class="field"><label for="tg{k}">or asset tags</label><input id="tg{k}" type="text" value={r.tags.join(', ')} onchange={(e) => (r.tags = L(e.currentTarget.value))} /></div>
      <div class="field"><label for="b{k}">From severity</label><select id="b{k}" bind:value={r.min_band}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
      <div class="field"><label for="t{k}">Team</label><input id="t{k}" type="text" bind:value={r.team} /></div>
      <div class="field"><label for="a{k}">Assign to (username)</label><input id="a{k}" type="text" bind:value={r.assign_to} /></div>
      <div class="field"><label for="tc{k}">Telegram chat ID</label><input id="tc{k}" type="text" bind:value={r.telegram_chat_id} /></div>
      <div class="field"><label for="sc{k}">Slack channel ID</label><input id="sc{k}" type="text" bind:value={r.slack_channel} /></div>
      <div class="field"><label for="em{k}">Email to</label><input id="em{k}" type="text" value={r.email_to.join(', ')} onchange={(e) => (r.email_to = L(e.currentTarget.value))} /></div>
      <label class="row small"><input type="checkbox" bind:checked={r.exclusive} /> Only this team (skip the default channels)</label>
      <div class="row"><label class="row small"><input type="checkbox" bind:checked={r.enabled} /> On</label><button class="btn small danger" onclick={() => (routes = routes.filter((x) => x !== r))}>Remove</button></div>
    </div>
  {/each}
  <div class="row"><button class="btn" onclick={add}>Add route</button><button class="btn primary" disabled={S.saving} onclick={() => save({ routes }, 'Routing saved.')}>Save routing</button></div>
</section>
<section class="card pad stack" aria-labelledby="tags"><h2 id="tags">Asset tags</h2>
  <p class="muted small">Tag hosts once (for example <code>pci</code>, <code>finance</code>) and route by tag.</p>
  <div class="table-wrap"><table><thead><tr><th>Host</th><th>Tags</th></tr></thead><tbody>
    {#each assets as a}<tr><td class="mono">{a.agent_name}</td><td><input type="text" aria-label="Tags for {a.agent_name}" value={(a.tags || []).join(', ')} onchange={(e) => (a.tags = L(e.currentTarget.value))} /></td></tr>
    {:else}<tr><td colspan="2" class="empty">Add assets under Rules first.</td></tr>{/each}</tbody></table></div>
  <button class="btn" style="align-self:flex-start" onclick={() => save({ assets }, 'Tags saved.')}>Save tags</button>
</section>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; align-items: end; }
  .route { padding: 12px; border: 1px solid var(--line); border-radius: 8px; }</style>
