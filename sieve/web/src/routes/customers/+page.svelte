<script>
  import { onMount } from 'svelte';
  import { get, post, put } from '$lib/api.js';
  import { app, toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  let list = $state([]), usage = $state({}), cross = $state([]), invite = $state(null);
  let t = $state({ name: '', wazuh_groups: '', host_patterns: '', color: '#0B6E69' });
  const L = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  async function load() {
    list = await get('/api/tenants');
    for (const x of list) usage[x.id] = await get(`/api/tenants/${x.id}/usage`).catch(() => null);
    if (!app.me?.tenant_id) cross = await get('/api/tenants/cross-attackers').catch(() => []);
  }
  onMount(load);
  async function add(e) { e.preventDefault();
    try { await post('/api/tenants', { name: t.name, wazuh_groups: L(t.wazuh_groups), host_patterns: L(t.host_patterns), brand: { color: t.color } });
      if (!app.multi) await put('/api/settings', { multi_tenant: true }).catch(() => {});
      toast(`${t.name} added. Its agents are mapped now and on every refresh.`); t = { name: '', wazuh_groups: '', host_patterns: '', color: '#0B6E69' }; load(); }
    catch (err) { toast(errText(err)); } }
  async function inv(x, role) { try { invite = { tenant: x.name, ...(await post('/api/users/invite-tenant', { role, tenant_id: x.id })) }; } catch (e) { toast(errText(e)); } }
  async function refresh() { try { const r = await post('/api/tenants/refresh-agents'); toast(`${r.agents} agents read from the Wazuh API.`); load(); } catch (e) { toast(errText(e)); } }
</script>
<svelte:head><title>Customers · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="row between" style="align-items:flex-end"><div class="stack" style="gap:6px"><h1>Customers</h1>
    <p class="muted">One Sieve, many customers. Agents map to customers through their Wazuh agent groups (read from the manager API) or host-name patterns. Customer users only ever see their own data.</p></div>
    {#if app.me?.role === 'admin' && !app.me?.tenant_id}<button class="btn" onclick={refresh}>Refresh agent groups from Wazuh</button>{/if}</header>
  {#if cross.length}
    <section class="card pad stack" aria-labelledby="xa"><h2 id="xa">Attackers hitting more than one customer</h2>
      <p class="muted small">The same source seen across customers in the last 7 days. Block once, protect everyone.</p>
      <div class="table-wrap"><table><thead><tr><th>Source IP</th><th>Customers</th><th class="num">Alerts</th><th>Last seen</th><th>Incidents</th></tr></thead><tbody>
        {#each cross as x}<tr><td class="mono">{x.srcip}</td><td>{x.tenants.map((t) => `${t.name} (${t.alerts})`).join(', ')}</td><td class="num">{x.alerts}</td>
          <td class="small">{new Date(x.last_seen).toLocaleString()}</td><td>{#each x.incidents as i}<a href="/incidents/{i.id}">#{i.id}</a> {/each}</td></tr>{/each}</tbody></table></div>
    </section>{/if}
  <div class="card table-wrap"><table><thead><tr><th>Customer</th><th>Mapping</th><th class="num">Agents</th><th class="num">Alerts (30 d)</th><th class="num">Incidents</th><th class="num">AI calls</th><th></th></tr></thead><tbody>
    {#each list as x}<tr><td><span class="sw" style="background:{x.brand?.color || '#999'}"></span> <strong>{x.name}</strong></td>
      <td class="small mono">{[...x.wazuh_groups.map((g) => 'group:' + g), ...x.host_patterns].join(', ') || '–'}</td>
      <td class="num">{usage[x.id]?.agents ?? '–'}</td><td class="num">{usage[x.id]?.alerts ?? '–'}</td><td class="num">{usage[x.id]?.incidents ?? '–'}</td><td class="num">{usage[x.id]?.ai_calls ?? '–'}</td>
      <td><div class="row"><a class="btn small" href="/summary?tenant={x.id}">Report</a>
        {#if app.me?.role === 'admin' && !app.me?.tenant_id}<button class="btn small" onclick={() => inv(x, 'analyst')}>Invite analyst</button><button class="btn small" onclick={() => inv(x, 'viewer')}>Invite viewer</button>{/if}</div></td></tr>
    {:else}<tr><td colspan="7" class="empty">No customers yet.</td></tr>{/each}</tbody></table></div>
  {#if invite}<div class="banner info stack" role="status"><strong>Invite link for {invite.tenant} ({invite.role}). Works once, expires in 72 hours.</strong><code style="word-break:break-all">{invite.url}</code></div>{/if}
  {#if app.me?.role === 'admin' && !app.me?.tenant_id}
  <section class="card pad stack" aria-labelledby="nc"><h2 id="nc">Add a customer</h2>
    <form class="grid" onsubmit={add}>
      <div class="field"><label for="n">Name</label><input id="n" type="text" required minlength="2" bind:value={t.name} /></div>
      <div class="field"><label for="g">Wazuh agent groups</label><input id="g" type="text" bind:value={t.wazuh_groups} placeholder="acme, acme-dmz" /></div>
      <div class="field"><label for="h">or host patterns</label><input id="h" type="text" bind:value={t.host_patterns} placeholder="acme-*" /></div>
      <div class="field"><label for="c">Report colour</label><input id="c" type="text" bind:value={t.color} pattern="#[0-9A-Fa-f]{'{6}'}" /></div>
      <button class="btn primary">Add customer</button></form>
  </section>{/if}
</div>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; align-items: end; }
  .sw { display: inline-block; width: 12px; height: 12px; border-radius: 3px; vertical-align: -1px; }</style>
