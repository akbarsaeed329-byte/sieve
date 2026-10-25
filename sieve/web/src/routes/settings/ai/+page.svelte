<script>
  // AI governance: treat models and tokens as privileged identities (Gartner 2026: MCP gateway, auditability).
  import { onMount } from 'svelte';
  import { get, post } from '$lib/api.js';
  import { toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  let p = $state(null), tenants = $state([]), shown = $state(null);
  let nt = $state({ name: 'claude-desktop-mcp', role: 'viewer', scopes: ['incidents:read', 'ask'], tenant_id: '', expires_in_days: 90 });
  const load = async () => { [p, tenants] = await Promise.all([get('/api/ai/permissions'), get('/api/tenants').catch(() => [])]); };
  onMount(load);
  async function mk(e) { e.preventDefault();
    try { shown = await post('/api/tokens/scoped', { ...nt, tenant_id: nt.tenant_id ? Number(nt.tenant_id) : null, expires_in_days: Number(nt.expires_in_days) }); load(); }
    catch (err) { toast(errText(err)); } }
</script>
{#if p}
<section class="card pad stack" aria-labelledby="mp"><h2 id="mp">What each model sees</h2>
  <p><strong>Model powers:</strong> {p.model_powers}</p>
  {#each p.providers as m}<div class="prov"><strong>{m.name}</strong> <span class="small muted">{m.model} · {m.cloud ? 'cloud' : 'local'}{m.enabled ? '' : ' · off'}</span>
    <ul class="small">{#each m.receives as r}<li>{r}</li>{/each}</ul></div>{/each}
  <p class="small"><strong>Never sent:</strong> {p.never_sent.join(' · ')}</p>
  <p class="small muted">Masking for cloud models: {p.masking_for_cloud ? 'on' : 'OFF'} · Budget: {p.budget_per_hour} calls per hour</p>
</section>
<section class="card pad stack" aria-labelledby="gw"><h2 id="gw">Scoped tokens (MCP gateway)</h2>
  <p class="muted small">Give AI assistants and scripts only what they need. A token's scopes limit which endpoints it can reach, a customer token only sees that customer, and every token is rate-limited and counted.</p>
  <form class="grid" onsubmit={mk}>
    <div class="field"><label for="tn">Name</label><input id="tn" type="text" required bind:value={nt.name} /></div>
    <div class="field"><label for="tr">Role</label><select id="tr" bind:value={nt.role}><option value="viewer">Viewer</option><option value="analyst">Analyst</option></select></div>
    <div class="field"><label for="tt">Customer</label><select id="tt" bind:value={nt.tenant_id}><option value="">All (provider)</option>{#each tenants as t}<option value={t.id}>{t.name}</option>{/each}</select></div>
    <div class="field"><label for="te">Expires after (days)</label><input id="te" type="number" min="1" max="730" bind:value={nt.expires_in_days} /></div>
    <fieldset class="row" style="border:none;padding:0;grid-column:1/-1"><legend class="small muted">Scopes</legend>
      {#each Object.keys(p.scopes).filter((x) => x !== 'admin') as sc}<label class="row small" title={p.scopes[sc].join(', ')}><input type="checkbox" checked={nt.scopes.includes(sc)}
        onchange={(e) => (nt.scopes = e.currentTarget.checked ? [...nt.scopes, sc] : nt.scopes.filter((x) => x !== sc))} /> {sc}</label>{/each}</fieldset>
    <button class="btn primary">Create scoped token</button></form>
  {#if shown}<div class="banner info stack" role="status"><strong>Copy it now. It will not be shown again.</strong><code style="word-break:break-all">{shown.token}</code>
    <span class="small">MCP: <code>sieve mcp --url {location.origin} --token {shown.token.slice(0, 10)}…</code></span></div>{/if}
  <div class="table-wrap"><table><thead><tr><th>Token</th><th>Role</th><th>Scopes</th><th>Customer</th><th class="num">Uses</th><th>Last used</th></tr></thead><tbody>
    {#each p.tokens as t}<tr class:muted={t.revoked}><td>{t.name}</td><td>{t.role}</td><td class="small mono">{t.scopes ? t.scopes.join(', ') : 'all for role'}</td>
      <td>{tenants.find((x) => x.id === t.tenant_id)?.name || '–'}</td><td class="num">{t.uses}</td><td class="small">{t.last_used_at ? new Date(t.last_used_at).toLocaleString() : 'never'}</td></tr>{/each}</tbody></table></div>
</section>
<section class="card pad stack" aria-labelledby="rc"><h2 id="rc">Recent AI calls</h2>
  <div class="table-wrap"><table><thead><tr><th>When</th><th>Provider</th><th>Purpose</th><th>Incident</th><th class="num">ms</th><th class="num">Tokens</th><th>OK</th></tr></thead><tbody>
    {#each p.recent_calls as c}<tr><td class="small">{new Date(c.at).toLocaleString()}</td><td>{c.provider}</td><td>{c.purpose}</td><td>{#if c.incident_id}<a href="/incidents/{c.incident_id}">#{c.incident_id}</a>{/if}</td>
      <td class="num">{c.latency_ms}</td><td class="num">{c.tokens}</td><td>{c.ok ? '✓' : '✕'}</td></tr>{:else}<tr><td colspan="7" class="empty">No AI calls yet.</td></tr>{/each}</tbody></table></div>
</section>
{/if}
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; align-items: end; }
  .prov { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; } .prov ul { margin: 6px 0 0; padding-left: 18px; }</style>
