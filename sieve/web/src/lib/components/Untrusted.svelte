<script>
  // Attacker-controlled text. Svelte escapes it; this box makes its origin unmistakable (doc 9.4).
  let { field, value, hit = false } = $props();
</script>
<div class="box" class:hit role="group" aria-label="Untrusted field {field}">
  <span class="lbl">Untrusted field: {field}{hit ? ' · tripwire' : ''}</span>
  <code>{value}</code>
</div>
<style>
  .box { border: 1px dashed var(--amber); background: var(--amber-bg); border-radius: 6px; padding: 8px 10px;
    display: flex; flex-direction: column; gap: 4px; }
  .hit { border-width: 2px; }
  .lbl { font-size: 12px; font-weight: 600; color: var(--amber-text); }
  code { color: var(--ink); word-break: break-word; white-space: pre-wrap; }
</style>
