<script>
  import { onMount } from 'svelte';
  import { del, get, post } from '$lib/api.js';
  import { toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  import { S, save } from '$lib/settings.svelte.js';
  import Secret from '$c/Secret.svelte';
  let tokens = $state([]), nt = $state({ name: '', role: 'viewer', expires_in_days: 90 }), shown = $state(null);
  let hooks = $state(JSON.parse(JSON.stringify(S.s.webhooks || [])));
  let jira = $state({ ...S.s.jira }), hive = $state({ ...S.s.thehive });
  const load = async () => (tokens = await get('/api/tokens'));
  onMount(load);
  async function mk(e) { e.preventDefault(); try { shown = await post('/api/tokens', { ...nt, expires_in_days: Number(nt.expires_in_days) }); load(); } catch (err) { toast(errText(err)); } }
  async function revoke(t) { if (!confirm(`Revoke token ${t.name}? Scripts using it stop working.`)) return; await del(`/api/tokens/${t.id}`).catch((e) => toast(errText(e))); load(); }
  const addHook = () => (hooks = [...hooks, { name: 'soar', url: 'https://', secret_env: 'SIEVE_WEBHOOK_SECRET', events: ['incident.notified', 'incident.escalated', 'incident.status_changed'], min_band: 'high', enabled: true }]);
  const EVENTS = ['incident.notified', 'incident.escalated', 'incident.status_changed'];
</script>
<section class="card pad stack" aria-labelledby="tk"><h2 id="tk">API tokens</h2>
  <p class="muted small">For scripts and SOAR tools: <code>Authorization: Bearer sv_…</code>. Only a hash is stored. See <a href="/api/docs">the API reference</a>.</p>
  <form class="row" onsubmit={mk}>
    <div class="field"><label for="t1">Name</label><input id="t1" type="text" required bind:value={nt.name} placeholder="tines-workflow" /></div>
    <div class="field"><label for="t2">Role</label><select id="t2" bind:value={nt.role}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></div>
    <div class="field"><label for="t3">Expires after (days)</label><input id="t3" type="number" min="1" max="730" bind:value={nt.expires_in_days} /></div>
    <button class="btn primary" style="align-self:flex-end">Create token</button></form>
  {#if shown}<div class="banner info stack" role="status"><strong>Copy it now. It will not be shown again.</strong><code style="word-break:break-all">{shown.token}</code>
    <button class="btn small" style="align-self:flex-start" onclick={() => navigator.clipboard?.writeText(shown.token).then(() => toast('Copied.'))}>Copy</button></div>{/if}
  <div class="table-wrap"><table><thead><tr><th>Name</th><th>Prefix</th><th>Role</th><th>Last used</th><th>Expires</th><th></th></tr></thead><tbody>
    {#each tokens as t}<tr class:muted={t.revoked}><td>{t.name}</td><td class="mono">{t.prefix}…</td><td>{t.role}</td><td class="small">{t.last_used_at ? new Date(t.last_used_at).toLocaleString() : 'never'}</td>
      <td class="small">{t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'never'}</td><td>{#if !t.revoked}<button class="btn small danger" onclick={() => revoke(t)}>Revoke</button>{:else}revoked{/if}</td></tr>
    {:else}<tr><td colspan="6" class="empty">No tokens.</td></tr>{/each}</tbody></table></div>
</section>
<section class="card pad stack" aria-labelledby="wh"><h2 id="wh">Webhooks</h2>
  <p class="muted small">Sieve POSTs JSON for each event and signs it: <code>X-Sieve-Signature: sha256=HMAC(secret, timestamp + "." + body)</code>. Only validated fields are sent, never raw log text.</p>
  {#each hooks as h, k}
    <div class="grid hook">
      <div class="field"><label for="hn{k}">Name</label><input id="hn{k}" type="text" bind:value={h.name} /></div>
      <div class="field"><label for="hu{k}">URL</label><input id="hu{k}" type="url" bind:value={h.url} /></div>
      <div class="field"><label for="hb{k}">From severity</label><select id="hb{k}" bind:value={h.min_band}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
      <div class="field"><label for="hs{k}">Signing secret variable</label><input id="hs{k}" type="text" bind:value={h.secret_env} /></div>
      <fieldset class="row" style="border:none;padding:0"><legend class="small muted">Events</legend>{#each EVENTS as ev}<label class="row small"><input type="checkbox" checked={h.events.includes(ev)} onchange={(e) => (h.events = e.currentTarget.checked ? [...h.events, ev] : h.events.filter((x) => x !== ev))} />{ev}</label>{/each}</fieldset>
      <div class="row"><label class="row small"><input type="checkbox" bind:checked={h.enabled} /> On</label><button class="btn small danger" onclick={() => (hooks = hooks.filter((x) => x !== h))}>Remove</button></div>
    </div>
  {/each}
  <div class="row"><button class="btn" onclick={addHook}>Add webhook</button><button class="btn primary" disabled={S.saving} onclick={() => save({ webhooks: hooks }, 'Webhooks saved. Store each signing secret below or in .env.')}>Save webhooks</button></div>
  {#each hooks.filter((h) => h.secret_env && /^SIEVE_[A-Z0-9_]{2,60}$/.test(h.secret_env)) as h}<Secret name={h.secret_env} label="Signing secret for {h.name} (save webhooks first)" />{/each}
</section>
<section class="card pad stack" aria-labelledby="jr"><h2 id="jr">Jira</h2>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={jira.enabled} /> Create an issue for each notified incident</label>
    <div class="field"><label for="j1">Site URL</label><input id="j1" type="url" bind:value={jira.base_url} placeholder="https://yourcompany.atlassian.net" /></div>
    <div class="field"><label for="j2">Account email</label><input id="j2" type="text" bind:value={jira.email} /></div>
    <div class="field"><label for="j3">Project key</label><input id="j3" type="text" bind:value={jira.project_key} placeholder="SEC" /></div>
    <div class="field"><label for="j4">Issue type</label><input id="j4" type="text" bind:value={jira.issue_type} /></div>
    <Secret name={jira.token_env} label="API token" /></div>
  <button class="btn primary" style="align-self:flex-start" onclick={() => save({ jira }, 'Jira saved.')}>Save Jira</button>
</section>
<section class="card pad stack" aria-labelledby="th"><h2 id="th">TheHive</h2>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={hive.enabled} /> Send notified incidents as TheHive alerts</label>
    <div class="field"><label for="h1">URL</label><input id="h1" type="url" bind:value={hive.base_url} placeholder="https://thehive.local:9000" /></div>
    <Secret name={hive.token_env} label="API key" /></div>
  <button class="btn primary" style="align-self:flex-start" onclick={() => save({ thehive: hive }, 'TheHive saved.')}>Save TheHive</button>
</section>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; align-items: end; }
  .hook { padding: 12px; border: 1px solid var(--line); border-radius: 8px; }</style>
