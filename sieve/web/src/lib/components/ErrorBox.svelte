<script>
  let { error } = $props();
</script>
{#if error}
  <div class="banner bad" role="alert">
    <div class="stack" style="gap:4px"><strong>{error.message || error}</strong>
      {#if error.fix}<span>{error.fix}</span>{/if}
      {#if error.code}<span class="small mono">{error.code}</span>{/if}</div>
  </div>
{/if}
