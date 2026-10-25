<script>
  import { post } from '$lib/api.js';
  import { errText } from '$lib/util.js';
  import Pill from '$c/Pill.svelte';
  import ErrorBox from '$c/ErrorBox.svelte';
  let q = $state(''), res = $state(null), error = $state(null), busy = $state(false), history = $state([]);
  const EX = ['What did 203.0.113.45 do this week?', 'Show open critical incidents', 'Which rules are noisiest?', 'Why were alerts suppressed today?'];
  async function go(e) { e?.preventDefault(); if (!q.trim()) return; busy = true; error = null;
    try { res = await post('/api/ask', { question: q }); history = [q, ...history.filter((x) => x !== q)].slice(0, 6); } catch (err) { error = err; } finally { busy = false; } }
</script>
<svelte:head><title>Ask · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="stack" style="gap:6px"><h1>Ask Sieve</h1>
    <p class="muted">Plain-English questions about your alerts. Answers come from fixed, read-only queries; the AI may only phrase the summary, and only with numbers and names that are in the result.</p></header>
  <form class="row" onsubmit={go}><label class="sr-only" for="q">Question</label>
    <input id="q" type="search" class="grow" style="flex:1 1 400px" placeholder="e.g. What did 203.0.113.45 do this week?" bind:value={q} />
    <button class="btn primary" disabled={busy}>Ask</button></form>
  <div class="row small">{#each [...history, ...EX.filter((x) => !history.includes(x))].slice(0, 6) as ex}<button class="chip" onclick={() => { q = ex; go(); }}>{ex}</button>{/each}</div>
  <ErrorBox {error} />
  {#if res}
    <section class="card pad stack" aria-live="polite">
      <p style="font-size:17px">{res.summary}</p>
      <p class="small muted">Understood as: {res.understood.intent}{res.understood.ip ? ` · IP ${res.understood.ip}` : ''}{res.understood.host ? ` · host ${res.understood.host}` : ''}{res.understood.user ? ` · user ${res.understood.user}` : ''} · last {res.understood.days} days · summary by {res.summary_source}</p>
      {#if res.answer.kind === 'entity'}
        <div class="kpis card"><div class="kpi"><span class="small muted">Alerts</span><span class="v">{res.answer.alerts}</span></div>
          <div class="kpi"><span class="small muted">Hosts</span><span class="v">{res.answer.hosts.length}</span></div>
          <div class="kpi"><span class="small muted">Incidents</span><span class="v">{res.answer.incidents.length}</span></div></div>
        {#if res.answer.hosts.length}<p class="small">Hosts: {res.answer.hosts.map(([h, n]) => `${h} (${n})`).join(', ')}</p>{/if}
        {#if res.answer.first_seen}<p class="small muted">First seen {new Date(res.answer.first_seen).toLocaleString()} · last seen {new Date(res.answer.last_seen).toLocaleString()}</p>{/if}
      {/if}
      {#if res.answer.incidents?.length}<div class="table-wrap"><table><tbody>{#each res.answer.incidents as i}<tr><td><Pill band={i.band} small /></td><td><a href="/incidents/{i.id}">#{i.id} {i.title}</a></td><td>{i.status.replace('_', ' ')}</td></tr>{/each}</tbody></table></div>{/if}
      {#if res.answer.rules}<div class="table-wrap"><table><thead><tr><th>Rule</th><th class="num">Alerts</th><th class="num">False positives</th><th>Suggestion</th></tr></thead><tbody>{#each res.answer.rules as r}<tr><td class="mono">{r.rule_id} <span class="muted small">{r.description}</span></td><td class="num">{r.alerts}</td><td class="num">{r.false_positives}</td><td class="small">{r.suggestion || '–'}</td></tr>{/each}</tbody></table></div>{/if}
      {#if res.answer.reasons}<ul>{#each res.answer.reasons as r}<li>{r.reason}: {r.count}</li>{/each}</ul>{/if}
    </section>
  {/if}
  <p class="small muted">Using your own AI assistant? Run <code>sieve mcp --url https://your-sieve --token sv_…</code> with a viewer token to give it the same read-only access.</p>
</div>
<style>.chip { border: 1px solid var(--line); background: var(--card); color: var(--ink); border-radius: 999px; padding: 6px 12px; cursor: pointer; font: inherit; min-height: 36px; }</style>
