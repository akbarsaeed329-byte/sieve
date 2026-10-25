<script>
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { get, post } from '$lib/api.js';
  import { app, loadMode } from '$lib/state.svelte.js';
  import ErrorBox from '$c/ErrorBox.svelte';
  let username = $state(''), password = $state(''), error = $state(null), busy = $state(false);
  async function submit(e) {
    e.preventDefault(); busy = true; error = null;
    try {
      await post('/api/auth/login', { username, password });
      app.me = await get('/api/auth/me'); loadMode(app.me.simple_mode_default);
      const next = page.url.searchParams.get('next');
      goto(next && next.startsWith('/') && !next.startsWith('//') ? next : '/');
    } catch (err) { error = err; } finally { busy = false; }
  }
</script>
<svelte:head><title>Sign in · Sieve</title></svelte:head>
<section class="card pad stack" style="margin-top:10vh">
  <h1>Sign in to Sieve</h1>
  <p class="muted">Use the account an admin created for you.</p>
  <form class="stack" onsubmit={submit}>
    <div class="field"><label for="u">Username</label><input id="u" type="text" autocomplete="username" bind:value={username} required /></div>
    <div class="field"><label for="p">Password</label><input id="p" type="password" autocomplete="current-password" bind:value={password} required /></div>
    <ErrorBox {error} />
    <button class="btn primary" disabled={busy}>Sign in</button>
  </form>
</section>
