<script>
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { app } from '$lib/state.svelte.js';
  import { S, loadSettings } from '$lib/settings.svelte.js';
  import ErrorBox from '$c/ErrorBox.svelte';
  let { children } = $props();
  onMount(loadSettings);
  let tabs = $derived([['integrations', 'Integrations'], ['models', 'Models'], ['plugins', 'Plugins'],
    ...(app.advanced ? [['rules', 'Rules']] : []), ['users', 'Users'], ['audit', 'Audit log']]);
</script>
<div class="stack-lg">
  <header class="stack" style="gap:6px"><h1>Settings</h1>
    <p class="muted">Changes are validated, saved to <code>settings.override.yaml</code> in the data folder, take effect at once, and are recorded in the audit log.{#if !app.advanced} Switch to Advanced to see Rules.{/if}</p></header>
  <nav class="tabs" aria-label="Settings sections">{#each tabs as [k, l]}<a href="/settings/{k}" aria-current={page.url.pathname.endsWith(k) ? 'page' : undefined}>{l}</a>{/each}</nav>
  {#if app.me?.role !== 'admin'}<p class="error">Only admins can change settings.</p>
  {:else}<ErrorBox error={S.error} />{#if S.s}{@render children()}{/if}{/if}
</div>
