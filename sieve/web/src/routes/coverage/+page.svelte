<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  import ErrorBox from '$c/ErrorBox.svelte';
  import { post } from '$lib/api.js';
  let c = $state(null), error = $state(null), show = $state('all'), tech = $state(''), d = $state(null);
  async function draft(t) { tech = t; d = await get(`/api/coverage/draft/${encodeURIComponent(t)}`).catch((e) => ({ available: false, message: e.message })); setTimeout(() => document.getElementById('draft')?.scrollIntoView({ behavior: 'smooth' }), 50); }
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
              onclick={(e) => { if (x.state === 'none' || x.state === 'missed') { e.preventDefault(); draft(x.id); } }}
              title="{x.id} {x.name}: {L[x.state]}{x.alerts ? `, ${x.alerts} alerts` : ''}"><span class="mono">{x.id}</span> {x.name}<span class="sr-only">: {L[x.state]}</span>{#if x.state === 'missed'} ✕{:else if x.state === 'detected'} ✓{/if}</a>
          {/each}
        </div>
      {/each}
    </div>
    <section class="card pad stack" id="draft" aria-labelledby="dr"><h2 id="dr">Close a gap</h2>
      <p class="muted small">Click a grey or red technique, or type one. Sieve shows a reviewed rule draft and backtests it on your last 30 days. It never deploys rules.</p>
      <form class="row" onsubmit={(e) => { e.preventDefault(); draft(tech); }}><input type="text" aria-label="Technique" bind:value={tech} placeholder="T1110" style="max-width:160px" /><button class="btn">Draft</button></form>
      {#if d}{#if d.available}<h3>{d.technique}: {d.title}</h3>
        <p class="small">Backtest (30 days): would fire {d.backtest?.would_fire ?? '?'} time(s){d.backtest?.would_have_caught?.length ? `, catching ${d.backtest.would_have_caught.length} incident(s)` : ''}.</p>
        <details open><summary class="small">Wazuh rule (add to local_rules.xml)</summary><pre class="log">{d.wazuh}</pre></details>
        <details><summary class="small">Sigma</summary><pre class="log">{d.sigma}</pre></details><p class="small muted">{d.note}</p>
      {:else}<p class="muted">{d.message}</p>{/if}{/if}
    </section>
  {/if}
</div>
<style>
  .matrix { display: grid; grid-auto-flow: column; grid-auto-columns: minmax(150px, 1fr); gap: 6px; overflow-x: auto; padding-bottom: 8px;
    width: 100%; max-width: 100%; min-width: 0; position: relative; }
  .col { display: flex; flex-direction: column; gap: 3px; }
  .col h3 { font-size: 12px; min-height: 32px; }
  .cell { font-size: 11px; line-height: 1.3; padding: 4px 6px; border-radius: 4px; text-decoration: none; color: var(--ink); border: 1px solid var(--line); }
  .cell.none { background: var(--neutral-bg); color: var(--muted); }
  .cell.rule, .leg.rule { background: var(--med-bg); }
  .cell.detected, .leg.detected { background: #D8F0E2; color: #14532D; }
  .cell.missed, .leg.missed { background: var(--crit-bg); color: var(--crit); font-weight: 600; }
  .leg[aria-pressed=true] { outline: 2px solid var(--brand); }
</style>
