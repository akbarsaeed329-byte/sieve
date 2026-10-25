<script>
  import { onMount } from 'svelte';
  import { get, post } from '$lib/api.js';
  import { app, toast } from '$lib/state.svelte.js';
  import { errText, ago } from '$lib/util.js';
  let users = $state([]), role = $state('analyst'), link = $state(null);
  const load = async () => (users = await get('/api/users'));
  onMount(load);
  async function invite() { try { link = await post('/api/users/invite', { role }); } catch (e) { toast(errText(e)); } }
  async function setRole(u, r) { try { await post(`/api/users/${u.id}/role`, { role: r }); toast(`${u.username} is now ${r}.`); } catch (e) { toast(errText(e)); } load(); }
</script>
<section class="card pad stack" aria-labelledby="inv"><h2 id="inv">Invite someone</h2>
  <div class="row"><div class="field"><label for="r">Role</label><select id="r" bind:value={role}><option value="viewer">Viewer: read only</option><option value="analyst">Analyst: handle incidents</option><option value="admin">Admin: everything</option></select></div>
    <button class="btn primary" style="align-self:flex-end" onclick={invite}>Create invite link</button></div>
  {#if link}<div class="banner info stack" role="status"><strong>Send this link privately. It works once and expires in {link.expires_in_hours} hours.</strong>
    <code style="word-break:break-all">{link.url}</code><button class="btn small" style="align-self:flex-start" onclick={() => navigator.clipboard?.writeText(link.url).then(() => toast('Copied.'))}>Copy link</button></div>{/if}
</section>
<div class="card table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Trainee</th><th>Last sign-in</th><th>Created</th></tr></thead><tbody>
  {#each users as u (u.id)}<tr><td>{u.username}{u.id === app.me?.id ? ' (you)' : ''}{u.locked ? ' · locked' : ''}</td>
    <td><select aria-label="Role for {u.username}" value={u.role} onchange={(e) => setRole(u, e.currentTarget.value)}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></td>
    <td><input type="checkbox" aria-label="Trainee {u.username}" checked={u.trainee} onchange={async (e) => { await post(`/api/users/${u.id}/trainee`, { trainee: e.currentTarget.checked }).catch((err) => toast(errText(err))); load(); }} /></td>
    <td class="muted">{u.last_login_at ? ago(u.last_login_at) + ' ago' : 'never'}</td><td class="muted">{new Date(u.created_at).toLocaleDateString()}</td></tr>{/each}
</tbody></table></div>
