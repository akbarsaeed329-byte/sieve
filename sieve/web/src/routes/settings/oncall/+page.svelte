<script>
  import { onMount } from 'svelte';
  import { del, get, post } from '$lib/api.js';
  import { toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  let d = $state(null), users = $state([]), r = $state({ name: 'Weekly', members: [], shift_hours: 168 });
  const load = async () => { [d, users] = await Promise.all([get('/api/oncall'), get('/api/users/directory')]); };
  onMount(load);
  async function add(e) { e.preventDefault(); try { await post('/api/oncall', { ...r, shift_hours: Number(r.shift_hours) }); toast('Rotation saved.'); load(); } catch (err) { toast(errText(err)); } }
</script>
{#if d}<section class="card pad stack" aria-labelledby="now"><h2 id="now">On call now</h2>
  <p style="font-size:18px">{d.now.length ? d.now.join(', ') : 'Nobody: escalations go to the default channels only.'}</p>
  <p class="small muted">When a high or critical incident misses its SLA, Sieve pages whoever is on call: a push to their installed Sieve app and an email, plus the normal channels.</p>
  {#each d.rotations as x}<div class="rot"><div class="row between"><strong>{x.name}</strong><button class="btn small" onclick={async () => { await del(`/api/oncall/${x.id}`).catch((e) => toast(errText(e))); load(); }}>Remove</button></div>
    <ol class="small">{#each x.next as s}<li>{s.user}: {new Date(s.from).toLocaleString()} → {new Date(s.to).toLocaleString()}</li>{/each}</ol></div>{/each}
</section>{/if}
<section class="card pad stack" aria-labelledby="nr"><h2 id="nr">New rotation</h2>
  <form class="stack" onsubmit={add}>
    <div class="row"><div class="field"><label for="n">Name</label><input id="n" type="text" required bind:value={r.name} /></div>
      <div class="field"><label for="s">Shift length (hours)</label><input id="s" type="number" min="1" bind:value={r.shift_hours} /></div></div>
    <fieldset class="row" style="border:none;padding:0"><legend class="small muted">People, in order</legend>
      {#each users as u}<label class="row small"><input type="checkbox" checked={r.members.includes(u.username)} onchange={(e) => (r.members = e.currentTarget.checked ? [...r.members, u.username] : r.members.filter((x) => x !== u.username))} /> {u.username}</label>{/each}</fieldset>
    <button class="btn primary" style="align-self:flex-start" disabled={!r.members.length}>Save rotation</button></form>
</section>
<style>.rot { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; } .rot ol { margin: 6px 0 0; padding-left: 18px; }</style>
