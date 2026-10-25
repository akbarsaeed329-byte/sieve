<script>
  import { BAND } from '$lib/util.js';
  let { band, small = false } = $props();
</script>
<!-- Severity is never carried by colour alone: the text label is always present. -->
<span class="pill {band}" class:small>{BAND[band] || band}</span>
<style>
  .pill { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 13px; font-weight: 600; white-space: nowrap; }
  .small { padding: 3px 9px; font-size: 12px; }
  .critical { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit-bd); }
  .high { background: var(--high-bg); color: var(--high); }
  .medium { background: var(--med-bg); color: var(--med); }
  .low { background: var(--low-bg); color: var(--low); }
  .suppressed { background: var(--neutral-bg); color: var(--soft); }
</style>
