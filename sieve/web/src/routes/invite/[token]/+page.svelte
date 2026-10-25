<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { get, post } from '$lib/api.js';
  import { app } from '$lib/state.svelte.js';
  import ErrorBox from '$c/ErrorBox.svelte';
  let info = $state(null), error = $state(null), username = $state(''), password = $state('');
  onMount(async () => { try { info = await get(`/api/invites/${encodeURIComponent(page.params.token)}`); } catch (e) { error = e; } });
  async function submit(e) {
    e.preventDefault(); error = null;
    try { await post(`/api/invites/${encodeURIComponent(page.params.token)}/accept`, { username, password });
      app.me = await get('/api/auth/me'); goto('/'); } catch (err) { error = err; }
  }
</script>
<section class="card pad stack" style="margin-top:10vh">
  <h1>Join Sieve</h1>
  {#if info}
    <p class="muted">You were invited as <strong>{info.role}</strong>. Choose a username and a passphrase of 12 or more characters.</p>
    <form class="stack" onsubmit={submit}>
      <div class="field"><label for="u">Username</label><input id="u" type="text" autocomplete="username" bind:value={username} required /></div>
      <div class="field"><label for="p">Password</label><input id="p" type="password" autocomplete="new-password" minlength="12" bind:value={password} required /></div>
      <ErrorBox {error} />
      <button class="btn primary">Create my account</button>
    </form>
  {:else}<ErrorBox {error} />{/if}
</section>
