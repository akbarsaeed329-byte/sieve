<script>
  // First-run wizard (doc 9.2, master prompt 2.1.1): admin -> Wazuh -> AI -> notifications -> test alert.
  // Each step tests its own connection, shows success or the fix, and can be skipped.
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { get, post, put } from '$lib/api.js';
  import { app, loadMode } from '$lib/state.svelte.js';
  import ErrorBox from '$c/ErrorBox.svelte';

  const STEPS = ['Admin account', 'Connect Wazuh', 'Choose AI', 'Notifications', 'Test alert'];
  let step = $state(0), error = $state(null), busy = $state(false), result = $state(null);
  let admin = $state({ username: '', password: '' });
  let wz = $state({ api_url: '', indexer_url: '', dashboard_url: '', username: 'wazuh-wui', password: '', verify_tls: true });
  let ai = $state({ mode: 'local', base_url: 'http://ollama:11434', model: 'llama3.1:8b', cloud_url: '', cloud_model: '', key: '' });
  let tg = $state({ chat_id: '', token: '' });
  let test = $state(null), started = 0;

  onMount(async () => {
    const st = await get('/api/setup/status');
    if (!st.needs_admin) {
      try { app.me = await get('/api/auth/me'); step = 1; } catch { goto('/login'); }
    }
  });

  async function run(fn) { busy = true; error = null; result = null; try { await fn(); } catch (e) { error = e; } finally { busy = false; } }
  const mark = (name, state = 'done') => post('/api/setup/progress', { step: name, state }).catch(() => {});
  function next(state = 'done') { mark(STEPS[step], state); result = null; error = null; step += 1; }

  const createAdmin = (e) => { e.preventDefault(); run(async () => {
    await post('/api/setup', admin); app.me = await get('/api/auth/me'); loadMode(true); step = 1; }); };

  const saveWazuh = () => run(async () => {
    await put('/api/settings', { wazuh: { api_url: wz.api_url, indexer_url: wz.indexer_url, dashboard_url: wz.dashboard_url,
      username: wz.username, verify_tls: wz.verify_tls } });
    if (wz.password) await put('/api/secrets', { name: 'SIEVE_WAZUH_PASSWORD', value: wz.password });
    const r = await post('/api/health/test/wazuh'); result = r;
    });

  const saveAI = () => run(async () => {
    let providers = [];
    if (ai.mode === 'local') providers = [{ name: 'local-ollama', kind: 'ollama', base_url: ai.base_url, model: ai.model, timeout_s: 90 }];
    if (ai.mode === 'cloud') {
      providers = [{ name: 'cloud', kind: 'openai_compatible', base_url: ai.cloud_url, model: ai.cloud_model,
        api_key_env: 'SIEVE_CLOUD_API_KEY', is_cloud: true, timeout_s: 30 }];
    }
    await put('/api/settings', { llm: { enabled: ai.mode !== 'none', providers } });
    if (ai.mode === 'cloud' && ai.key) await put('/api/secrets', { name: 'SIEVE_CLOUD_API_KEY', value: ai.key });
    result = ai.mode === 'none' ? { ok: true, message: 'No AI: Sieve sends rule-based alerts with evidence. You can add a model later.' }
      : await post(`/api/health/test/llm/${providers[0].name}`); });

  const saveTelegram = () => run(async () => {
    await put('/api/settings', { notify: { telegram: { enabled: true, chat_id: tg.chat_id } } });
    if (tg.token) await put('/api/secrets', { name: 'SIEVE_TELEGRAM_TOKEN', value: tg.token });
    result = await post('/api/health/test/notify/telegram'); });

  const fire = () => run(async () => {
    const r = await post('/api/setup/test-alert'); started = performance.now(); test = { pending: true };
    for (let i = 0; i < 30; i++) {
      await new Promise((ok) => setTimeout(ok, 700));
      const s = await get(`/api/setup/test-alert/${encodeURIComponent(r.wazuh_id)}`);
      if (s.processed) { test = { ...s, ms: Math.round(performance.now() - started) }; return; }
    }
    throw { message: 'The test alert was not processed within 20 seconds.', fix: 'Open Health and check the triage worker.' }; });

  async function finish() { await mark('Test alert'); goto('/'); }
</script>

<svelte:head><title>Set up Sieve</title></svelte:head>
<div class="stack-lg" style="margin-top:4vh">
  <header class="stack" style="gap:6px"><h1>Set up Sieve</h1>
    <p class="muted">About 10 minutes. Every step can be skipped and finished later in Settings.</p></header>
  <ol class="steps" aria-label="Setup progress">
    {#each STEPS as s, i}<li class:done={i < step} aria-current={i === step ? 'step' : undefined}><span>{i + 1}</span>{s}</li>{/each}
  </ol>

  <section class="card pad stack" aria-live="polite">
    {#if step === 0}
      <h2>Create the admin account</h2>
      <p class="muted">You can invite colleagues later. Use a passphrase of 12 or more characters.</p>
      <form class="stack" onsubmit={createAdmin}>
        <div class="field"><label for="au">Username</label><input id="au" type="text" autocomplete="username" bind:value={admin.username} required /></div>
        <div class="field"><label for="ap">Password</label><input id="ap" type="password" autocomplete="new-password" minlength="12" bind:value={admin.password} required /></div>
        <ErrorBox {error} />
        <button class="btn primary" disabled={busy}>Create admin and continue</button>
      </form>
    {:else if step === 1}
      <h2>Connect Wazuh</h2>
      <p class="muted">Alerts can be pushed to Sieve by the Wazuh integration (see the README). Connecting the API adds
        "Show query" links, investigation checks and the coverage map. Use a read-only user.</p>
      <div class="grid">
        <div class="field"><label for="w1">Manager API URL</label><input id="w1" type="url" placeholder="https://wazuh.manager:55000" bind:value={wz.api_url} /></div>
        <div class="field"><label for="w2">Indexer URL</label><input id="w2" type="url" placeholder="https://wazuh.indexer:9200" bind:value={wz.indexer_url} /></div>
        <div class="field"><label for="w3">Dashboard URL</label><input id="w3" type="url" placeholder="https://wazuh.local" bind:value={wz.dashboard_url} /></div>
        <div class="field"><label for="w4">API user</label><input id="w4" type="text" bind:value={wz.username} /></div>
        <div class="field"><label for="w5">API password</label><input id="w5" type="password" autocomplete="off" bind:value={wz.password} />
          <span class="hint">Stored encrypted; never shown again.</span></div>
        <label class="row"><input type="checkbox" bind:checked={wz.verify_tls} /> Verify TLS certificates</label>
      </div>
      {@render outcome()}
      <div class="row"><button class="btn primary" onclick={saveWazuh} disabled={busy || !wz.api_url}>Save and test</button>
        <button class="btn" onclick={() => next(result?.ok ? 'done' : 'skipped')}>{result?.ok ? 'Continue' : 'Skip for now'}</button></div>
    {:else if step === 2}
      <h2>Choose AI</h2>
      <p class="muted">The model only explains. Severity always comes from rules, so Sieve works fully without AI.</p>
      <fieldset class="stack"><legend class="sr-only">AI mode</legend>
        <label class="opt"><input type="radio" bind:group={ai.mode} value="local" /> <span><strong>Local model (Ollama)</strong><br /><span class="hint">Private: logs stay on this machine.</span></span></label>
        <label class="opt"><input type="radio" bind:group={ai.mode} value="cloud" /> <span><strong>Cloud model</strong><br /><span class="hint">Any OpenAI-compatible API. IPs, users and host names are masked before sending.</span></span></label>
        <label class="opt"><input type="radio" bind:group={ai.mode} value="none" /> <span><strong>No AI</strong><br /><span class="hint">Rule-based summaries with evidence only.</span></span></label>
      </fieldset>
      {#if ai.mode === 'local'}
        <div class="grid"><div class="field"><label for="o1">Ollama URL</label><input id="o1" type="url" bind:value={ai.base_url} /></div>
          <div class="field"><label for="o2">Model</label><input id="o2" type="text" bind:value={ai.model} /></div></div>
      {:else if ai.mode === 'cloud'}
        <div class="banner trip small" role="note">Alert details leave this machine when a cloud model is used. Masking is on by default.</div>
        <div class="grid"><div class="field"><label for="c1">Base URL</label><input id="c1" type="url" placeholder="https://provider/v1" bind:value={ai.cloud_url} /></div>
          <div class="field"><label for="c2">Model</label><input id="c2" type="text" bind:value={ai.cloud_model} /></div>
          <div class="field"><label for="c3">API key</label><input id="c3" type="password" autocomplete="off" bind:value={ai.key} /></div></div>
      {/if}
      {@render outcome()}
      <div class="row"><button class="btn primary" onclick={saveAI} disabled={busy}>Save and test</button>
        <button class="btn" onclick={() => next(result?.ok ? 'done' : 'skipped')}>{result?.ok ? 'Continue' : 'Skip for now'}</button></div>
    {:else if step === 3}
      <h2>Connect Telegram</h2>
      <p class="muted">Create a bot with @BotFather, send it a message, then get your chat ID from @userinfobot. Slack and Discord are in Settings.</p>
      <div class="grid"><div class="field"><label for="t1">Chat ID</label><input id="t1" type="text" bind:value={tg.chat_id} /></div>
        <div class="field"><label for="t2">Bot token</label><input id="t2" type="password" autocomplete="off" bind:value={tg.token} /></div></div>
      {@render outcome()}
      <div class="row"><button class="btn primary" onclick={saveTelegram} disabled={busy || !tg.chat_id}>Save and send test</button>
        <button class="btn" onclick={() => next(result?.ok ? 'done' : 'skipped')}>{result?.ok ? 'Continue' : 'Skip for now'}</button></div>
    {:else}
      <h2>Fire a test alert</h2>
      <p class="muted">Sieve queues a synthetic alert and runs it through the full pipeline, exactly like a real one.</p>
      {#if test?.processed}
        <p class="ok-text">Processed in {test.ms} ms. Incident #{test.incident_id} was created.</p>
        {#each test.notifications as n}<p class="small">{n.channel}: {n.ok ? `sent in ${n.latency_ms} ms` : `failed: ${n.error}`}</p>{/each}
      {:else if test?.pending}<p class="muted">Waiting for the worker…</p>{/if}
      <ErrorBox {error} />
      <div class="row"><button class="btn" onclick={fire} disabled={busy}>Send test alert</button>
        <button class="btn primary" onclick={finish}>Go to the dashboard</button></div>
    {/if}
  </section>
</div>

{#snippet outcome()}
  {#if result}
    {#if result.ok}<p class="ok-text" role="status">✓ {result.message || 'Connected.'}</p>
    {:else if result.checks}
      {#each Object.entries(result.checks) as [k, v]}
        <div class={v.ok ? 'ok-text' : 'banner bad'}>{k}: {v.ok ? '✓ connected' : `${v.message} ${v.fix || ''} (${v.code})`}</div>
      {/each}
    {:else}<ErrorBox error={result} />{/if}
  {/if}
  <ErrorBox {error} />
{/snippet}

<style>
  .steps { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 8px; }
  .steps li { display: flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 999px; background: var(--card);
    border: 1px solid var(--line); font-size: 13px; color: var(--muted); }
  .steps li span { font-weight: 600; }
  .steps li[aria-current=step] { border-color: var(--brand); color: var(--ink); font-weight: 600; }
  .steps li.done { color: var(--ok); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; }
  fieldset { border: none; padding: 0; margin: 0; }
  .opt { display: flex; gap: 10px; align-items: flex-start; padding: 12px; border: 1px solid var(--line); border-radius: 8px; cursor: pointer; }
</style>
