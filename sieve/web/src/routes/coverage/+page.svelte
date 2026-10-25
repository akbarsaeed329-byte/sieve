<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  import ErrorBox from '$c/ErrorBox.svelte';
  let c = $state(null), error = $state(null), show = $state('all');
  onMount(async () => { try { c = await get('/api/coverage'); } catch (e) { error = e; } });
  const L = { missed: 'Tested and missed', detected: 'Tested and detected', rule: 'Rule exists', none: 'No rule seen' };
</script>
<svelte:head><title>Coverage · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="stack" style="gap:6px"><h1>Detection coverage</h1>
    <p class="muted">MITRE ATT&amp;CK techniques your Wazuh rules cover. Green and red come from Atomic Red Team or benchmark runs in the last 30 days.</p></header>
  <ErrorBox {error} />
  {#if c}
    <div class="row" role="group" aria-label="Legend and filter">
      {#each ['missed', 'detected', 'rule', 'none'] as s}<button class="btn small leg {s}" aria-pressed={show === s} onclick={() => (show = show === s ? 'all' : s)}>{L[s]} ({c.totals[s] || 0})</button>{/each}
    </div>
    <p class="small muted">Rules from: {c.rule_source === 'wazuh-api' ? 'the Wazuh API' : 'techniques seen in alerts (connect the Wazuh API for the full rule list)'} · ATT&amp;CK {c.catalogue_version}</p>
    <div class="matrix" role="list">
      {#each c.tactics as t}
        <div class="col" role="listitem"><h3>{t.name}</h3>
          {#each t.techniques.filter((x) => show === 'all' || x.state === show) as x}
            <a class="cell {x.state}" href="https://attack.mitre.org/techniques/{x.id}/" target="_blank" rel="noopener noreferrer"
              title="{x.id} {x.name}: {L[x.state]}{x.alerts ? `, ${x.alerts} alerts` : ''}"><span class="mono">{x.id}</span> {x.name}<span class="sr-only">: {L[x.state]}</span>{#if x.state === 'missed'} ✕{:else if x.state === 'detected'} ✓{/if}</a>
          {/each}
        </div>
      {/each}
    </div>
  {/if}
</div>
<style>
  .matrix { display: grid; grid-auto-flow: column; grid-auto-columns: minmax(150px, 1fr); gap: 6px; overflow-x: auto; padding-bottom: 8px; }
  .col { display: flex; flex-direction: column; gap: 3px; }
  .col h3 { font-size: 12px; min-height: 32px; }
  .cell { font-size: 11px; line-height: 1.3; padding: 4px 6px; border-radius: 4px; text-decoration: none; color: var(--ink); border: 1px solid var(--line); }
  .cell.none { background: var(--neutral-bg); color: var(--muted); }
  .cell.rule, .leg.rule { background: var(--med-bg); }
  .cell.detected, .leg.detected { background: #D8F0E2; color: #14532D; }
  .cell.missed, .leg.missed { background: var(--crit-bg); color: var(--crit); font-weight: 600; }
  .leg[aria-pressed=true] { outline: 2px solid var(--brand); }
</style>
