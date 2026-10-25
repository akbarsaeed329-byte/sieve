<script>
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { get, post } from '$lib/api.js';
  import { app, loadMode } from '$lib/state.svelte.js';
  import ErrorBox from '$c/ErrorBox.svelte';
  import { onMount } from 'svelte';
  let sso = $state(null);
  onMount(async () => { sso = await get('/api/auth/oidc/config').catch(() => null); });
  let username = $state(''), password = $state(''), otp = $state(''), needOtp = $state(false), error = $state(null), busy = $state(false);
  async function submit(e) {
    e.preventDefault(); busy = true; error = null;
    try {
      await post('/api/auth/login', { username, password, otp: otp || undefined });
      app.me = await get('/api/auth/me'); loadMode(app.me.simple_mode_default);
      const next = page.url.searchParams.get('next');
      goto(next && next.startsWith('/') && !next.startsWith('//') ? next : '/');
    } catch (err) { if (err.code === 'SIEVE-AUTH-449') { needOtp = true; error = otp ? err : null; } else error = err; } finally { busy = false; }
  }
</script>
<svelte:head><title>Sign in · Sieve</title></svelte:head>
<section class="card pad stack" style="margin-top:10vh">
  <h1>Sign in to Sieve</h1>
  <p class="muted">Use the account an admin created for you.</p>
  <form class="stack" onsubmit={submit}>
    <div class="field"><label for="u">Username</label><input id="u" type="text" autocomplete="username" bind:value={username} required /></div>
    <div class="field"><label for="p">Password</label><input id="p" type="password" autocomplete="current-password" bind:value={password} required /></div>
    {#if needOtp}<div class="field"><label for="o">6-digit code from your authenticator app</label><input id="o" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="8" bind:value={otp} required /></div>{/if}
    <ErrorBox {error} />
    <button class="btn primary" disabled={busy}>Sign in</button>
  </form>
  {#if sso?.enabled}<div class="row" style="justify-content:center"><span class="muted small">or</span></div><a class="btn" href="/api/auth/oidc/start" data-sveltekit-reload>{sso.label}</a>{/if}
</section>
