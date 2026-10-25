<script>
  import { onMount } from 'svelte';
  import { get, post } from '$lib/api.js';
  import { canEdit, toast } from '$lib/state.svelte.js';
  import { ago, errText } from '$lib/util.js';
  import ErrorBox from '$c/ErrorBox.svelte';
  let d = $state(null), recent = $state(null), error = $state(null);
  async function load() {
    try { [d, recent] = await Promise.all([get('/api/suppressions?sampled=true'), get('/api/suppressions?limit=50')]); }
    catch (e) { error = e; }
  }
  onMount(load);
  async function review(x, outcome) {
    try { const r = await post(`/api/suppressions/${x.id}/review`, { outcome });
      toast(r.flag ? `Restored and re-queued. ${r.flag}` : 'Confirmed as noise.'); load(); }
    catch (e) { toast(errText(e)); }
  }
  let done = $derived(d ? d.items.filter((x) => x.outcome).length : 0);
</script>
<svelte:head><title>Hidden alerts · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="stack" style="gap:6px"><h1>Check what was hidden</h1>
    <p class="muted">Nothing is suppressed silently. Each week Sieve samples 20 suppressed alerts at random; confirm they were noise or restore them. Restored alerts go back through triage, and the filter that hid them is flagged.</p></header>
  <ErrorBox {error} />
  {#if d}
  <section class="stack" aria-labelledby="s1">
    <div class="row between"><h2 id="s1">This week's sample ({d.week})</h2><span class="small muted">{done} of {d.items.length} checked</span></div>
    <div class="card table-wrap"><table>
      <thead><tr><th>Alert</th><th>Host</th><th>Why it was hidden</th><th>When</th><th>Decision</th></tr></thead>
      <tbody>{#each d.items as x (x.id)}<tr>
        <td><strong>{x.description}</strong><br /><span class="small muted mono">rule {x.rule_id} · level {x.level ?? '–'}</span>
          {#if x.full_log}<pre class="log" style="margin-top:6px">{x.full_log}</pre>{/if}</td>
        <td class="mono">{x.agent_name || '–'}</td><td>{x.reason}</td><td class="muted">{ago(x.created_at)} ago</td>
        <td>{#if x.outcome}<span class:ok-text={x.outcome === 'noise'} class:error={x.outcome === 'restored'}>{x.outcome === 'noise' ? 'Noise' : 'Restored'}</span><br /><span class="small muted">{x.reviewed_by}</span>
          {:else if canEdit()}<div class="row"><button class="btn small" onclick={() => review(x, 'noise')}>It was noise</button>
            <button class="btn small danger" onclick={() => review(x, 'restore')}>Bring it back</button></div>{:else}<span class="muted">Not reviewed</span>{/if}</td>
      </tr>{:else}<tr><td colspan="5" class="empty">Nothing was suppressed in the last 7 days.</td></tr>{/each}</tbody>
    </table></div>
  </section>
  <section class="stack" aria-labelledby="s2">
    <h2 id="s2">Suppression reasons</h2>
    <div class="card table-wrap"><table><thead><tr><th>Reason</th><th class="num">Alerts</th><th class="num">Restored by reviewers</th></tr></thead>
      <tbody>{#each d.by_reason as r}<tr><td>{r.reason}{#if r.flagged} <span class="error small">· flagged: hid an alert someone brought back. Review it in Settings › Rules.</span>{/if}</td>
        <td class="num">{r.count.toLocaleString()}</td><td class="num">{r.restored}</td></tr>{/each}</tbody></table></div>
    <p class="small muted">{d.total.toLocaleString()} alerts suppressed in total. Last week reviewers restored {d.last_week_restored}.</p>
  </section>
  {/if}
</div>
