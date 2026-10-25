<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  let d = $state({ items: [], total: 0 }), offset = $state(0), action = $state('');
  const load = async () => { try { d = await get(`/api/audit?limit=50&offset=${offset}${action ? '&action=' + encodeURIComponent(action) : ''}`); } catch { /* access denied or offline: keep the page usable */ } };
  onMount(load);
</script>
<p class="muted">Append-only: the database refuses to change or delete entries. Secrets are never recorded, only that they changed.</p>
<div class="row"><div class="field"><label for="a">Action starts with</label><input id="a" type="search" placeholder="incident., settings., auth." bind:value={action} oninput={() => { offset = 0; load(); }} /></div></div>
<div class="card table-wrap"><table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>
  {#each d.items as e (e.id)}<tr><td class="small">{new Date(e.at).toLocaleString()}</td><td>{e.actor}</td><td class="mono">{e.action}</td><td class="mono">{e.target}</td>
    <td>{#if Object.keys(e.detail || {}).length}<details><summary class="small">Show</summary><pre class="log">{JSON.stringify(e.detail, null, 2)}</pre></details>{/if}</td></tr>{/each}
</tbody></table></div>
<div class="row"><button class="btn small" disabled={offset === 0} onclick={() => { offset = Math.max(0, offset - 50); load(); }}>Newer</button>
  <span class="small muted">{d.total ? offset + 1 : 0}–{Math.min(offset + 50, d.total)} of {d.total}</span>
  <button class="btn small" disabled={offset + 50 >= d.total} onclick={() => { offset += 50; load(); }}>Older</button></div>
