<script>
  let { label = 'tripwire' } = $props();
</script>
<span class="trip">{label}</span>
<style>
  .trip { display: inline-block; padding: 2px 7px; border-radius: 6px; border: 1px dashed var(--amber);
    color: var(--amber-text); background: var(--amber-bg); font-size: 12px; font-weight: 600; white-space: nowrap; }
</style>
