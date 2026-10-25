<script>
  import { onMount } from 'svelte';
  import { get, post } from '$lib/api.js';
  import { S, save } from '$lib/settings.svelte.js';
  import Secret from '$c/Secret.svelte';
  let llm = $state(JSON.parse(JSON.stringify(S.s.llm)));
  let status = $state(null), tests = $state({}), drag = $state(-1);
  let add = $state({ name: '', kind: 'openai_compatible', base_url: '', model: '', is_cloud: true });
  onMount(async () => { status = (await get('/api/health/details').catch(() => null))?.llm; });
  function move(i, d) { const j = i + d; if (j < 0 || j >= llm.providers.length) return;
    const p = [...llm.providers]; [p[i], p[j]] = [p[j], p[i]]; llm.providers = p; }
  function drop(i) { if (drag < 0 || drag === i) return; const p = [...llm.providers]; const [x] = p.splice(drag, 1); p.splice(i, 0, x); llm.providers = p; drag = -1; }
  function addProvider() {
    if (!add.name || !add.base_url || !add.model) return;
    const env = 'SIEVE_' + add.name.toUpperCase().replace(/[^A-Z0-9]/g, '_') + '_KEY';
    llm.providers = [...llm.providers, { ...add, api_key_env: add.kind === 'openai_compatible' ? env : null, timeout_s: add.is_cloud ? 30 : 90, enabled: true }];
    add = { name: '', kind: 'openai_compatible', base_url: '', model: '', is_cloud: true };
  }
  async function test(p) { tests[p.name] = { pending: true }; try { tests[p.name] = await post(`/api/health/test/llm/${encodeURIComponent(p.name)}`); } catch (e) { tests[p.name] = { ok: false, ...e }; } }
  const st = (name) => status?.providers.find((x) => x.name === name);
  let used = $derived(status?.budget.used || 0);
</script>
<section class="card pad stack" aria-labelledby="fb"><h2 id="fb">Fallback order</h2>
  <p class="muted small">Sieve tries each model in order and falls back on errors, rate limits or an open circuit breaker. Drag rows, or use the arrow buttons. "No AI" is always the last resort: notifications never wait for a model. Save, then press Test.</p>
  <ol class="list">
    {#each llm.providers as p, i (p.name)}
      <li draggable="true" ondragstart={() => (drag = i)} ondragover={(e) => e.preventDefault()} ondrop={() => drop(i)} class:dragging={drag === i}>
        <span class="handle" aria-hidden="true">⋮⋮</span>
        <div class="grow stack" style="gap:2px"><strong>{i + 1}. {p.name}</strong>
          <span class="small muted">{p.kind === 'ollama' ? 'Ollama' : 'OpenAI-compatible'} · {p.model} · {p.base_url} · {p.is_cloud ? 'cloud (data leaves this machine)' : 'local'}</span>
          {#if st(p.name)}<span class="small">State: {st(p.name).state}, circuit {st(p.name).circuit}{st(p.name).retry_in_s ? `, retry in ${st(p.name).retry_in_s}s` : ''} · {st(p.name).calls} calls, {st(p.name).tokens} tokens</span>{/if}
          {#if tests[p.name]?.pending}<span class="small muted">Testing…</span>{:else if tests[p.name]}<span class="small {tests[p.name].ok ? 'ok-text' : 'error'}">{tests[p.name].message} {tests[p.name].fix || ''}</span>{/if}
          {#if p.api_key_env}<Secret name={p.api_key_env} label="API key" />{/if}
        </div>
        <label class="row small"><input type="checkbox" bind:checked={p.enabled} /> On</label>
        <button class="btn small" onclick={() => test(p)}>Test</button>
        <button class="btn small" aria-label="Move {p.name} up" onclick={() => move(i, -1)}>↑</button>
        <button class="btn small" aria-label="Move {p.name} down" onclick={() => move(i, 1)}>↓</button>
        <button class="btn small danger" aria-label="Remove {p.name}" onclick={() => (llm.providers = llm.providers.filter((x) => x !== p))}>✕</button>
      </li>
    {/each}
    <li class="last"><span class="handle" aria-hidden="true">·</span><div class="grow"><strong>No AI</strong> <span class="small muted">rule-based facts with evidence; always available</span></div></li>
  </ol>
  <details><summary>Add a model</summary>
    <div class="grid" style="margin-top:12px">
      <div class="field"><label for="m1">Name</label><input id="m1" type="text" bind:value={add.name} placeholder="groq-free" /></div>
      <div class="field"><label for="m2">Type</label><select id="m2" bind:value={add.kind}><option value="openai_compatible">OpenAI-compatible</option><option value="ollama">Ollama</option></select></div>
      <div class="field"><label for="m3">Base URL</label><input id="m3" type="url" bind:value={add.base_url} /></div>
      <div class="field"><label for="m4">Model</label><input id="m4" type="text" bind:value={add.model} /></div>
      <label class="row"><input type="checkbox" bind:checked={add.is_cloud} /> Cloud service</label>
      <button class="btn" onclick={addProvider}>Add to the end</button></div>
  </details>
</section>
<section class="card pad stack" aria-labelledby="qb"><h2 id="qb">Quota and privacy</h2>
  <div class="grid">
    <label class="row"><input type="checkbox" bind:checked={llm.enabled} /> Use AI explanations</label>
    <div class="field"><label for="q1">Calls per hour (all models)</label><input id="q1" type="number" min="0" bind:value={llm.calls_per_hour} /></div>
    <div class="field"><label for="q2">Explain incidents from</label><select id="q2" bind:value={llm.min_band}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></div>
    <label class="row"><input type="checkbox" bind:checked={llm.mask_for_cloud} /> Mask IPs, users and host names before any cloud call</label>
    <label class="row"><input type="checkbox" bind:checked={llm.investigate_critical} /> Run read-only investigation checks for critical incidents</label>
  </div>
  <div class="stack" style="gap:4px"><span class="small">This hour: {used} of {llm.calls_per_hour} calls</span>
    <div class="quota" role="progressbar" aria-valuemin="0" aria-valuemax={llm.calls_per_hour} aria-valuenow={used} aria-label="AI calls used this hour">
      <i style="width:{Math.min(100, (100 * used) / Math.max(1, llm.calls_per_hour))}%" class:warn={used > 0.8 * llm.calls_per_hour}></i></div></div>
  {#if !llm.mask_for_cloud && llm.providers.some((p) => p.is_cloud)}<div class="banner trip small" role="note">Masking is off: usernames, IPs and host names will be sent to a cloud provider.</div>{/if}
  <button class="btn primary" style="align-self:flex-start" disabled={S.saving} onclick={() => save({ llm }, 'Model settings saved.')}>Save model settings</button>
</section>
<style>
  .list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 8px; }
  .list li { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--card); }
  .list li.dragging { opacity: 0.5; } .list li.last { border-style: dashed; }
  .handle { cursor: grab; color: var(--muted); user-select: none; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; align-items: end; }
  .quota { height: 8px; background: var(--line-2); border-radius: 999px; overflow: hidden; max-width: 420px; }
  .quota i { display: block; height: 100%; background: var(--brand); } .quota i.warn { background: var(--amber); }
</style>
