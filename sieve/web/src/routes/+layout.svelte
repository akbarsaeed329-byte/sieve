<script>
  import '@fontsource/ibm-plex-sans/400.css';
  import '@fontsource/ibm-plex-sans/500.css';
  import '@fontsource/ibm-plex-sans/600.css';
  import '@fontsource/ibm-plex-mono/400.css';
  import '@fontsource/ibm-plex-mono/500.css';
  import '../app.css';
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { get, post } from '$lib/api.js';
  import { app, loadMode, setAdvanced } from '$lib/state.svelte.js';
  import Light from '$c/Light.svelte';

  let { children } = $props();
  let ready = $state(false);
  const PUBLIC = ['/login', '/setup', '/invite'];
  const isPublic = (p) => PUBLIC.some((x) => p === x || p.startsWith(x + '/'));

  async function boot() {
    try {
      const st = await get('/api/setup/status');
      if (st.needs_admin) { app.me = null; if (page.url.pathname !== '/setup') await goto('/setup'); return; }
      try {
        app.me = await get('/api/auth/me');
        loadMode(app.me.simple_mode_default);
      } catch {
        app.me = null;
        if (!isPublic(page.url.pathname)) await goto('/login?next=' + encodeURIComponent(page.url.pathname));
      }
    } finally { ready = true; }
  }

  async function refreshHealth() {
    if (!app.me) return;
    try { app.health = await get('/api/health/details'); } catch { /* shown as unknown */ }
  }

  onMount(() => {
    boot().then(refreshHealth);
    const h = setInterval(refreshHealth, 30000);
    const out = () => { app.me = null; goto('/login'); };
    window.addEventListener('sieve:signed-out', out);
    return () => { clearInterval(h); window.removeEventListener('sieve:signed-out', out); };
  });

  // Load health as soon as someone is signed in (not only on the 30 s timer).
  $effect(() => { if (app.me) refreshHealth(); });
  $effect(() => { if (app.me?.must_enroll_2fa && !page.url.pathname.startsWith('/settings/security')) goto('/settings/security'); });

  async function logout() { await post('/api/auth/logout').catch(() => {}); app.me = null; goto('/login'); }

  let nav = $derived([
    { href: '/', label: 'Overview' },
    { href: '/incidents', label: 'Incidents' },
    { href: '/ask', label: 'Ask Sieve' },
    ...(app.advanced ? [{ href: '/investigate', label: 'Investigate' }, { href: '/coverage', label: 'Coverage' },
      { href: '/reports', label: 'Metrics' }, { href: '/tuning', label: 'Tuning' }] : []),
    ...(app.advanced || app.me?.trainee ? [{ href: '/practice', label: 'Practice' }] : []),
    { href: '/hidden', label: 'Hidden alerts' },
    { href: '/summary', label: 'Reports' },
    { href: '/health', label: 'Health' },
    ...(app.me?.role === 'admin' ? [{ href: '/settings/integrations', label: 'Settings' }] : [])
  ]);
  const active = (href) => href === '/' ? page.url.pathname === '/' : page.url.pathname.startsWith(href.split('/').slice(0, 2).join('/'));
  let shell = $derived(app.me && !isPublic(page.url.pathname));
  let topComponents = $derived((app.health?.components || []).filter((c) => !c.id.startsWith('queue')).slice(0, 7));
</script>

<a class="skip" href="#main">Skip to content</a>
{#if !ready}
  <p class="muted" style="padding:32px">Loading…</p>
{:else if shell}
  <div class="app">
    <nav aria-label="Main">
      <a class="brand" href="/" aria-label="Sieve overview">
        <svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true" fill="none" stroke="var(--brand)" stroke-width="1.75"><circle cx="14" cy="14" r="11"/><path d="M6 11h16M5 15h18M7 19h14M11 4v20M17 4v20"/></svg>
        <span>Sieve</span>
      </a>
      <div class="links">
        {#each nav as n}<a href={n.href} aria-current={active(n.href) ? 'page' : undefined}>{n.label}</a>{/each}
      </div>
      <a class="health" href="/health" aria-label="System health, open details">
        <span class="small" style="font-weight:600;color:var(--muted)">System health</span>
        {#each topComponents as c}
          <span class="hrow"><Light light={c.light} label={c.name} />{c.name}<span class="hstate">{({green:'OK',amber:'Warning',red:'Problem',unknown:'–'})[c.light]}</span></span>
        {:else}<span class="small muted">Checking…</span>{/each}
      </a>
      <div class="bottom">
        {#if app.health?.shadow_mode}<span class="small" style="color:var(--amber-text)">Shadow mode: no notifications are sent</span>{/if}
        <span class="small muted">View</span>
        <div class="seg" role="group" aria-label="View mode">
          <button type="button" aria-pressed={!app.advanced} onclick={() => setAdvanced(false)}>Simple</button>
          <button type="button" aria-pressed={app.advanced} onclick={() => setAdvanced(true)}>Advanced</button>
        </div>
        <span class="small muted">{app.me.username} · {app.me.role}</span>
        <button type="button" class="btn small" onclick={logout}>Sign out</button>
      </div>
    </nav>
    <main id="main" tabindex="-1">{@render children()}</main>
  </div>
{:else}
  <main id="main" class="public" tabindex="-1">{@render children()}</main>
{/if}
{#if app.toast}<div class="toast" role="status" aria-live="polite">{app.toast}</div>{/if}

<style>
  .skip { position: absolute; left: -999px; }
  .skip:focus { left: 8px; top: 8px; z-index: 10; background: var(--card); padding: 8px; }
  .app { display: flex; flex-wrap: wrap; min-height: 100vh; }
  nav { flex: 1 1 232px; max-width: 280px; padding: 24px 20px; background: var(--nav); border-right: 1px solid var(--line);
    display: flex; flex-direction: column; gap: 28px; }
  @media (max-width: 760px) { nav { max-width: none; flex-basis: 100%; } }
  .brand { display: flex; align-items: center; gap: 10px; font-size: 20px; font-weight: 600; color: var(--ink); text-decoration: none; }
  .links { display: flex; flex-direction: column; gap: 4px; }
  .links a { display: flex; align-items: center; padding: 10px 12px; min-height: 44px; border-radius: 8px; color: var(--ink);
    text-decoration: none; border: 1px solid transparent; }
  .links a[aria-current=page] { background: var(--card); border-color: var(--line); font-weight: 600; }
  .health { display: flex; flex-direction: column; gap: 8px; font-size: 13px; color: var(--ink); text-decoration: none; }
  .hrow { display: flex; align-items: center; gap: 8px; }
  .hstate { margin-left: auto; color: var(--muted); }
  .bottom { margin-top: auto; display: flex; flex-direction: column; gap: 8px; }
  .seg { display: flex; border: 1px solid var(--input); border-radius: 8px; overflow: hidden; background: var(--card); }
  .seg button { flex: 1; min-height: 40px; border: none; background: var(--card); color: var(--ink); font: 500 13px var(--sans); cursor: pointer; }
  .seg button[aria-pressed=true] { background: var(--ink); color: var(--ground); }
  main { flex: 999 1 560px; min-width: 0; padding: 32px 40px 48px; }
  @media (max-width: 760px) { main { padding: 20px 16px; } }
  main.public { max-width: 720px; margin: 0 auto; }
  .toast { position: fixed; bottom: 20px; right: 20px; max-width: 420px; background: var(--ink); color: var(--ground);
    padding: 12px 16px; border-radius: 8px; z-index: 20; }
</style>
