<script>
  // Incident queue table with keyboard navigation: J/K move, Enter or E open, A acknowledge.
  import { goto } from '$app/navigation';
  import { post } from '$lib/api.js';
  import { ago, STATUS, errText, until } from '$lib/util.js';
  import { canEdit, toast } from '$lib/state.svelte.js';
  import Pill from '$c/Pill.svelte';
  import Trip from '$c/Trip.svelte';
  let { items = [], onchange = () => {}, caption = 'Incident queue' } = $props();
  let sel = $state(-1);

  async function ack(i) {
    if (!canEdit()) return toast('Viewers cannot acknowledge incidents.');
    try { await post(`/api/incidents/${i.id}/acknowledge`); toast(`${i.ref} acknowledged.`); onchange(); }
    catch (e) { toast(errText(e)); }
  }
  function key(e) {
    if (e.target.closest('input, textarea, select') || e.metaKey || e.ctrlKey || e.altKey || !items.length) return;
    const k = e.key.toLowerCase();
    if (k === 'j') { sel = Math.min(items.length - 1, sel + 1); e.preventDefault(); }
    else if (k === 'k') { sel = Math.max(0, sel - 1); e.preventDefault(); }
    else if ((k === 'enter' || k === 'e') && sel >= 0) { goto(`/incidents/${items[sel].id}${k === 'e' ? '#evidence' : ''}`); }
    else if (k === 'a' && sel >= 0) { ack(items[sel]); }
    else return;
    document.getElementById(`row-${sel}`)?.scrollIntoView({ block: 'nearest' });
  }
</script>
<svelte:window onkeydown={key} />
<div class="card table-wrap">
  <table style="min-width:760px">
    <caption class="sr-only">{caption}. Keys: J and K move, E opens evidence, A acknowledges.</caption>
    <thead><tr><th scope="col">Severity</th><th scope="col">Incident</th><th scope="col">Host</th><th scope="col">User</th>
      <th scope="col" class="num">Alerts</th><th scope="col">Age</th><th scope="col">Status</th><th scope="col">Owner</th></tr></thead>
    <tbody>
      {#each items as i, n (i.id)}
        <tr id="row-{n}" class:sel={n === sel} aria-selected={n === sel}>
          <td><Pill band={i.band} small /></td>
          <td><a href="/incidents/{i.id}" style="color:var(--ink);font-weight:600">{i.title}</a>
            {#if i.tripwire}<Trip />{/if}{#if i.is_selftest}<span class="small muted"> · test</span>{/if}
            {#if i.partial_context}<span class="small muted"> · partial context</span>{/if}
            {#if i.status === 'new' && i.sla_due && until(i.sla_due).overdue}<span class="small" style="color:var(--crit);font-weight:600"> · SLA overdue</span>{/if}
            {#if i.maintenance}<span class="small muted"> · maintenance</span>{/if}</td>
          <td class="mono nw">{i.agent_name || '–'}</td>
          <td class="mono nw">{i.user || '–'}</td>
          <td class="num">{i.alert_count.toLocaleString()}</td>
          <td class="muted nw">{ago(i.opened_at)}</td>
          <td class="nw">{STATUS[i.status] || i.status}</td>
          <td class:muted={!i.assignee}>{i.assignee || 'Unassigned'}</td>
        </tr>
      {:else}<tr><td colspan="8" class="empty">No incidents.</td></tr>{/each}
    </tbody>
  </table>
</div>
<p class="small muted">Keys: <kbd>J</kbd>/<kbd>K</kbd> move · <kbd>E</kbd> evidence · <kbd>A</kbd> acknowledge</p>
<style>.nw { white-space: nowrap; }</style>
