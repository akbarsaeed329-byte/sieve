<script>
  import { onMount } from 'svelte';
  import { del, get, put } from '$lib/api.js';
  import { app, tq, toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  import Pill from '$c/Pill.svelte';
  let layout = $state([]), avail = $state([]), d = $state(null), editing = $state(false);
  const NAMES = { kpis: 'Key numbers', open_by_band: 'Open by severity', sla_breaches: 'Past SLA', top_hosts: 'Most targeted hosts (7 d)',
    top_ips: 'Top source IPs (7 d)', risk_top: 'Highest-risk entities', open_by_owner: 'Open by owner', tripwires: 'Manipulation attempts (7 d)',
    compliance_due: 'Regulatory deadlines < 24 h', silent_sources: 'Silent log sources', noise_trend: 'New incidents per day' };
  async function load() {
    try { const l = await get('/api/dashboard'); layout = l.widgets; avail = l.available; d = await get(`/api/dashboard/data${tq('?')}`); }
    catch (e) { toast(errText(e)); }
  }
  onMount(() => { const t = setInterval(load, 30000); return () => clearInterval(t); });
  $effect(() => { app.tenant; load(); });
  async function save() { try { layout = (await put('/api/dashboard', { widgets: layout })).widgets; editing = false; toast('Dashboard saved.'); } catch (e) { toast(errText(e)); } }
  const move = (k, dir) => { const j = k + dir; if (j < 0 || j >= layout.length) return; const l = [...layout]; [l[k], l[j]] = [l[j], l[k]]; layout = l; };
  const hm = (m) => (m < 0 ? `${Math.abs(m)} min overdue` : m < 120 ? `${m} min left` : `${Math.round(m / 60)} h left`);
</script>
<svelte:head><title>Dashboard · Sieve</title></svelte:head>
<div class="stack-lg">
  <header class="row between" style="align-items:flex-end"><div class="stack" style="gap:6px"><h1>Dashboard</h1><p class="muted">Your own view. Pick the tiles you need; each person's layout is saved separately.</p></div>
    {#if editing}<div class="row"><button class="btn" onclick={() => { editing = false; load(); }}>Cancel</button><button class="btn primary" onclick={save}>Save layout</button></div>
    {:else}<button class="btn" onclick={() => (editing = true)}>Customise</button>{/if}</header>
  {#if editing}
    <section class="card pad stack"><h2>Tiles</h2>
      {#each layout as w, k}<div class="row tile-row"><span class="grow">{NAMES[w]}</span><button class="btn small" aria-label="Move up" onclick={() => move(k, -1)}>↑</button>
        <button class="btn small" aria-label="Move down" onclick={() => move(k, 1)}>↓</button><button class="btn small danger" onclick={() => (layout = layout.filter((x) => x !== w))}>Remove</button></div>{/each}
      <div class="row">{#each avail.filter((w) => !layout.includes(w)) as w}<button class="btn small" onclick={() => (layout = [...layout, w])}>+ {NAMES[w]}</button>{/each}</div>
    </section>
  {/if}
  {#if d}<div class="tiles">
    {#each layout as w (w)}<section class="card pad stack tile" aria-label={NAMES[w]}><h2 style="font-size:15px">{NAMES[w]}</h2>
      {#if w === 'kpis'}<div class="kpis"><div class="kpi"><span class="small muted">Open</span><span class="v">{d.kpis.open}</span></div><div class="kpi"><span class="small muted">Critical open</span><span class="v">{d.kpis.critical_open}</span></div>
          <div class="kpi"><span class="small muted">Alerts 24 h</span><span class="v">{d.kpis.alerts_24h.toLocaleString()}</span></div><div class="kpi"><span class="small muted">Sent 24 h</span><span class="v">{d.kpis.notifications_24h}</span></div></div>
      {:else if w === 'open_by_band'}{#each ['critical', 'high', 'medium', 'low'] as b}<div class="row between"><Pill band={b} small /><strong>{d.open_by_band[b] || 0}</strong></div>{/each}
      {:else if w === 'sla_breaches' || w === 'tripwires'}{#each d[w] as i}<a href="/incidents/{i.id}">#{i.id} {i.title}</a>{:else}<span class="muted small">None.</span>{/each}
      {:else if w === 'top_hosts' || w === 'top_ips' || w === 'open_by_owner'}{#each d[w] as [k, n]}<div class="row between"><span class="mono small">{k}</span><span>{n}</span></div>{:else}<span class="muted small">None.</span>{/each}
      {:else if w === 'risk_top'}{#each d.risk_top as r}<div class="stack" style="gap:2px"><div class="row between"><span class="mono small">{r.entity}</span><span class="small">{r.points} / {r.threshold}</span></div>
          <div class="bar"><i style="width:{Math.min(100, (100 * r.points) / r.threshold)}%" class:hot={r.points >= r.threshold}></i></div></div>{:else}<span class="muted small">No risk accumulated.</span>{/each}
      {:else if w === 'compliance_due'}{#each d.compliance_due as c}<a href="/incidents/{c.id}" class="small">{c.regime.toUpperCase()} · {c.item} · #{c.id}: <strong class:error={c.minutes_left < 0}>{hm(c.minutes_left)}</strong></a>{:else}<span class="muted small">Nothing due.</span>{/each}
      {:else if w === 'silent_sources'}{#each d.silent_sources as a}<span class="small"><span class="mono">{a.agent_name}</span>: silent {a.silent_hours} h</span>{:else}<span class="ok-text small">All sources reporting.</span>{/each}
      {:else if w === 'noise_trend'}<div class="spark">{#each d.noise_trend as [day, n]}<div title="{day}: {n}" style="height:{Math.max(4, 6 * n)}px"></div>{/each}</div><span class="small muted">{d.noise_trend.map(([a, b]) => `${a}: ${b}`).join(' · ') || 'No incidents this week.'}</span>{/if}
    </section>{/each}
  </div>{/if}
</div>
<style>.tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(320px, 100%), 1fr)); gap: 16px; align-items: start; }
  .tile-row { padding: 6px 0; border-bottom: 1px solid var(--line-2); }
  .bar { height: 6px; background: var(--line-2); border-radius: 999px; overflow: hidden; } .bar i { display: block; height: 100%; background: var(--amber); } .bar i.hot { background: var(--bad); }
  .spark { display: flex; align-items: flex-end; gap: 4px; height: 70px; } .spark div { flex: 1; background: var(--brand); border-radius: 3px 3px 0 0; }</style>
