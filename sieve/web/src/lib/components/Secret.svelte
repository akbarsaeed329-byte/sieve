<script>
  // Write-only secret input: the current value is never sent to the browser.
  import { S, setSecret, secretLabel } from '$lib/settings.svelte.js';
  let { name, label } = $props();
  let value = $state('');
  const id = `sec-${name}`;
</script>
<div class="field">
  <label for={id}>{label} <span class="small">({secretLabel(S.secrets[name])})</span></label>
  <div class="row" style="flex-wrap:nowrap">
    <input {id} type="password" autocomplete="off" placeholder={S.secrets[name] === 'unset' ? '' : '••••••••'} bind:value />
    <button class="btn small" type="button" disabled={!value || S.secrets[name] === 'env'} onclick={() => { setSecret(name, value); value = ''; }}>Store</button>
    {#if S.secrets[name] === 'stored'}<button class="btn small" type="button" onclick={() => setSecret(name, '')}>Clear</button>{/if}
  </div>
  <span class="hint">Env var <code>{name}</code> overrides this.</span>
</div>
