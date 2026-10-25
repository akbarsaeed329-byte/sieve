<script>
  // Settings forms are generated from each plugin's JSON Schema manifest (doc 10.3).
  import { onMount } from 'svelte';
  import { get, put } from '$lib/api.js';
  import { toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  import Secret from '$c/Secret.svelte';
  import { S } from '$lib/settings.svelte.js';
  let list = $state([]), forms = $state({}), pending = $state(null);
  async function load() {
    list = await get('/api/plugins');
    for (const p of list) { forms[p.id] = { ...p.config }; Object.assign(S.secrets, p.secrets); }
  }
  onMount(load);
  async function toggle(p, enabled, approve = false) {
    try { await put(`/api/plugins/${p.id}`, { enabled, approve_permissions: approve }); pending = null; toast(`${p.name} ${enabled ? 'enabled' : 'disabled'}.`); load(); }
    catch (e) { if (e.code === 'SIEVE-PLG-428') pending = p; else toast(errText(e)); load(); }
  }
  async function saveCfg(p) {
    const cfg = {};
    for (const [k, spec] of Object.entries(p.settings_schema.properties)) if (!spec['x-secret-name']) cfg[k] = spec.type === 'integer' ? Number(forms[p.id][k]) : forms[p.id][k];
    try { await put(`/api/plugins/${p.id}`, { config: cfg }); toast('Plugin settings saved.'); } catch (e) { toast(errText(e)); }
  }
</script>
{#each list as p (p.id)}
  <section class="card pad stack" aria-labelledby="p-{p.id}">
    <div class="row between"><div class="stack" style="gap:2px"><h2 id="p-{p.id}">{p.name} <span class="small muted">{p.type} · v{p.version}</span></h2><span class="muted">{p.description}</span></div>
      <label class="row"><input type="checkbox" checked={p.enabled} onchange={(e) => toggle(p, e.currentTarget.checked)} /> Enabled</label></div>
    <p class="small">Permissions: network {p.permissions.network?.join(', ') || 'none'} · reads alerts: {p.permissions.read_alerts ? 'yes' : 'no'} · can trigger response: {p.permissions.trigger_response ? 'yes' : 'no'}</p>
    {#if pending?.id === p.id}
      <div class="banner trip stack" role="alertdialog" aria-label="Approve permissions">
        <strong>Approve {p.name}'s permissions?</strong><span>It will be allowed to contact {p.permissions.network?.join(', ')}. Only public source IPs are sent.</span>
        <div class="row"><button class="btn primary" onclick={() => toggle(p, true, true)}>Approve and enable</button><button class="btn" onclick={() => (pending = null)}>Cancel</button></div></div>
    {/if}
    <div class="grid">
      {#each Object.entries(p.settings_schema.properties) as [k, spec]}
        {#if spec['x-secret-name']}<Secret name={spec['x-secret-name']} label={spec.title || k} />
        {:else if spec.type === 'boolean'}<label class="row"><input type="checkbox" bind:checked={forms[p.id][k]} /> {spec.title || k}</label>
        {:else if spec.enum}<div class="field"><label for="{p.id}-{k}">{spec.title || k}</label><select id="{p.id}-{k}" bind:value={forms[p.id][k]}>{#each spec.enum as o}<option value={o}>{o}</option>{/each}</select></div>
        {:else}<div class="field"><label for="{p.id}-{k}">{spec.title || k}</label><input id="{p.id}-{k}" type={spec.type === 'integer' || spec.type === 'number' ? 'number' : 'text'} min={spec.minimum} max={spec.maximum} bind:value={forms[p.id][k]} /></div>{/if}
      {/each}
    </div>
    <button class="btn" style="align-self:flex-start" onclick={() => saveCfg(p)}>Save settings</button>
  </section>
{:else}<p class="muted">No plugins installed.</p>{/each}
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; align-items: end; }</style>
