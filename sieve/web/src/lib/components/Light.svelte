<script>
  let { light = 'unknown', label = '' } = $props();
  const words = { green: 'OK', amber: 'Warning', red: 'Problem', unknown: 'Unknown' };
</script>
<span class="dot {light}" role="img" aria-label="{label} {words[light] || light}"></span>
<style>
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 999px; flex: none; }
  .green { background: var(--ok); }
  .amber { background: var(--amber); }
  .red { background: var(--bad); }
  .unknown { background: transparent; border: 2px solid var(--muted); }
</style>
