<script>
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { app } from '$lib/state.svelte.js';
  import { S, loadSettings } from '$lib/settings.svelte.js';
  import ErrorBox from '$c/ErrorBox.svelte';
  let { children } = $props();
  onMount(loadSettings);
  let tabs = $derived(app.me?.role === 'admin' ? [['integrations', 'Integrations'], ['models', 'Models'], ['profile', 'Profile & floors'], ['routing', 'Routing'],
    ['correlation', 'Correlation'], ['exceptions', 'Exceptions & maintenance'],
    ['automation', 'Automation'], ['plugins', 'Plugins'], ...(app.advanced ? [['rules', 'Rules']] : []), ['users', 'Users'],
    ['security', 'Security'], ['audit', 'Audit log']] : [['security', 'Security']]);
</script>
<div class="stack-lg">
  <header class="stack" style="gap:6px"><h1>Settings</h1>
    <p class="muted">Changes are validated, saved to <code>settings.override.yaml</code> in the data folder, take effect at once, and are recorded in the audit log.{#if !app.advanced} Switch to Advanced to see Rules.{/if}</p></header>
  <nav class="tabs" aria-label="Settings sections">{#each tabs as [k, l]}<a href="/settings/{k}" aria-current={page.url.pathname.endsWith(k) ? 'page' : undefined}>{l}</a>{/each}</nav>
  {#if app.me?.role !== 'admin' && !page.url.pathname.endsWith('/security')}<p class="error">Only admins can change these settings.</p>
  {:else if app.me?.role !== 'admin'}{@render children()}
  {:else}<ErrorBox error={S.error} />{#if S.s}{@render children()}{/if}{/if}
</div>
