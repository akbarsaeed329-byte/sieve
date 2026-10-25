<script>
  import { post } from '$lib/api.js';
  import { toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  import { S, save } from '$lib/settings.svelte.js';
  import Secret from '$c/Secret.svelte';
  let wz = $state({ ...S.s.wazuh });
  let n = $state(JSON.parse(JSON.stringify(S.s.notify)));
  let teams = $state({ ...S.s.teams }), pd = $state({ ...S.s.pagerduty });
  let results = $state({});
  async function test(kind, path) {
    results[kind] = { pending: true };
    try { results[kind] = await post(path); } catch (e) { results[kind] = { ok: false, ...e }; }
  }
  const saveWazuh = () => save({ wazuh: wz }, 'Wazuh settings saved.');
  const saveNotify = () => save({ notify: n }, 'Notification settings saved.');
  async function digest() { try { await post('/api/digest/send?version=' + n.digest.version); toast('Digest sent.'); } catch (e) { toast(errText(e)); } }
</script>

{#snippet outcome(r)}
  {#if r?.pending}<p class="muted small">Testing…</p>
  {:else if r?.checks}{#each Object.entries(r.checks) as [k, v]}<p class={v.ok ? 'ok-text' : 'error'}>{k}: {v.ok ? '✓ connected' : `${v.message} ${v.fix || ''} (${v.code})`}</p>{/each}
  {:else if r}<p class={r.ok ? 'ok-text' : 'error'} role="status">{r.ok ? `✓ ${r.message}` : `${r.message} ${r.fix || ''} (${r.code})`}</p>{/if}
{/snippet}

<section class="card pad stack" aria-labelledby="wz"><h2 id="wz">Wazuh</h2>
  <p class="muted small">Alerts reach Sieve through the Wazuh integration script (push). These read-only credentials add investigation checks, "Show query" links, rule coverage and active response.</p>
  <div class="grid">
    <div class="field"><label for="a1">Manager API URL</label><input id="a1" type="url" bind:value={wz.api_url} placeholder="https://wazuh.manager:55000" /></div>
    <div class="field"><label for="a2">Indexer URL</label><input id="a2" type="url" bind:value={wz.indexer_url} placeholder="https://wazuh.indexer:9200" /></div>
    <div class="field"><label for="a3">Dashboard URL (for "Show query")</label><input id="a3" type="url" bind:value={wz.dashboard_url} /></div>
    <div class="field"><label for="a4">API user</label><input id="a4" type="text" bind:value={wz.username} /></div>
    <Secret name={wz.password_env} label="API password" />
    <div class="field"><label for="a5">Indexer user</label><input id="a5" type="text" bind:value={wz.indexer_username} /></div>
    <Secret name={wz.indexer_password_env} label="Indexer password" />
    <label class="row"><input type="checkbox" bind:checked={wz.verify_tls} /> Verify TLS certificates</label>
    <label class="row"><input id="pull" type="checkbox" bind:checked={wz.pull_enabled} disabled={!wz.indexer_url} /> Read alerts from the indexer (pull mode: nothing to install on the manager)</label>
    <div class="field"><label for="pi">Pull every (seconds)</label><input id="pi" type="number" min="5" max="3600" bind:value={wz.pull_interval_s} disabled={!wz.pull_enabled} /></div>
  </div>
  {#if !wz.indexer_url}<p class="hint">Pull mode needs the indexer URL and credentials.</p>{/if}
  {@render outcome(results.wazuh)}
  <div class="row"><button class="btn primary" onclick={saveWazuh} disabled={S.saving}>Save</button>
    <button class="btn" onclick={() => test('wazuh', '/api/health/test/wazuh')}>Test connection</button></div>
  <p class="small muted">Link alerts in the Wazuh dashboard to Sieve: in Dashboards Management › Index patterns › wazuh-alerts-*, set the <code>id</code> field's format to URL with template <code>{S.s.notify.public_url}/go/alert/{'{{value}}'}</code>.</p>
  <p class="small muted">Active response: {S.s.allow_active_response ? 'enabled (every action needs an admin to confirm it)' : 'disabled. It can only be enabled in the config file.'}</p>
</section>

<section class="card pad stack" aria-labelledby="nt"><h2 id="nt">Notifications</h2>
  <div class="grid">
    <div class="field"><label for="n1">Notify from severity</label><select id="n1" bind:value={n.min_band}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
      <span class="hint">Tripwire hits always notify.</span></div>
    <div class="field"><label for="n2">Sieve address used in links</label><input id="n2" type="url" bind:value={n.public_url} /></div>
    <label class="row"><input type="checkbox" bind:checked={n.console} /> Also print to the container log</label>
  </div>
  <h3>Telegram</h3>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={n.telegram.enabled} /> Enabled</label>
    <div class="field"><label for="t1">Chat ID</label><input id="t1" type="text" bind:value={n.telegram.chat_id} /></div>
    <Secret name={n.telegram.token_env} label="Bot token" /></div>
  {@render outcome(results.telegram)}
  <button class="btn small" style="align-self:flex-start" onclick={() => test('telegram', '/api/health/test/notify/telegram')}>Send test message</button>
  <h3>Slack</h3>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={n.slack.enabled} /> Enabled</label>
    <div class="field"><label for="s1">Channel ID (with a bot token)</label><input id="s1" type="text" bind:value={n.slack.channel} /></div>
    <Secret name={n.slack.token_env} label="Bot token (send and edit)" />
    <Secret name={n.slack.webhook_env} label="or incoming webhook URL (send only)" /></div>
  {@render outcome(results.slack)}
  <button class="btn small" style="align-self:flex-start" onclick={() => test('slack', '/api/health/test/notify/slack')}>Send test message</button>
  <h3>Discord</h3>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={n.discord.enabled} /> Enabled</label>
    <Secret name={n.discord.webhook_env} label="Webhook URL" /></div>
  {@render outcome(results.discord)}
  <button class="btn small" style="align-self:flex-start" onclick={() => test('discord', '/api/health/test/notify/discord')}>Send test message</button>
  <h3>Email</h3>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={n.email.enabled} /> Enabled</label>
    <div class="field"><label for="e1">SMTP host</label><input id="e1" type="text" bind:value={n.email.host} /></div>
    <div class="field"><label for="e2">Port (587 STARTTLS, 465 TLS)</label><input id="e2" type="number" bind:value={n.email.port} /></div>
    <div class="field"><label for="e3">Username</label><input id="e3" type="text" bind:value={n.email.username} /></div>
    <Secret name={n.email.password_env} label="SMTP password" />
    <div class="field"><label for="e4">From</label><input id="e4" type="text" bind:value={n.email.sender} /></div>
    <div class="field"><label for="e5">To (comma-separated)</label><input id="e5" type="text" value={n.email.to.join(', ')} onchange={(e) => (n.email.to = e.currentTarget.value.split(',').map((x) => x.trim()).filter(Boolean))} /></div></div>
  {@render outcome(results.email)}
  <button class="btn small" style="align-self:flex-start" onclick={() => test('email', '/api/health/test/notify/email')}>Send test email</button>
  <details><summary class="small">Buttons in Telegram and Slack (acknowledge from your phone)</summary>
    <ol class="small"><li>Telegram: store <code>SIEVE_TELEGRAM_WEBHOOK_SECRET</code>, then call <code>https://api.telegram.org/bot&lt;token&gt;/setWebhook?url={S.s.notify.public_url}/api/integrations/telegram/webhook&amp;secret_token=&lt;secret&gt;</code>.</li>
      <li>Slack: in your app, turn on Interactivity with request URL <code>{S.s.notify.public_url}/api/integrations/slack/actions</code> and store the signing secret as <code>SIEVE_SLACK_SIGNING_SECRET</code>.</li>
      <li>Each person links their chat account once: Settings › Security › Link Telegram or Slack.</li></ol></details>
  <h3>Microsoft Teams</h3>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={teams.enabled} /> Enabled</label><Secret name={teams.webhook_env} label="Workflows / incoming webhook URL" /></div>
  {@render outcome(results.teams)}
  <div class="row"><button class="btn small" onclick={() => save({ teams }, 'Teams saved.')}>Save Teams</button><button class="btn small" onclick={() => test('teams', '/api/health/test/notify/teams')}>Send test card</button></div>
  <h3>PagerDuty</h3>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={pd.enabled} /> Page on-call (resolves automatically when Sieve resolves)</label>
    <div class="field"><label for="pdb">From severity</label><select id="pdb" bind:value={pd.min_band}><option value="critical">Critical</option><option value="high">High</option></select></div>
    <Secret name={pd.routing_key_env} label="Events API v2 routing key" /></div>
  <button class="btn small" style="align-self:flex-start" onclick={() => save({ pagerduty: pd }, 'PagerDuty saved.')}>Save PagerDuty</button>
  <h3>Daily digest</h3>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={n.digest.enabled} /> Send a daily digest</label>
    <div class="field"><label for="d1">Hour (UTC)</label><input id="d1" type="number" min="0" max="23" bind:value={n.digest.hour_utc} /></div>
    <div class="field"><label for="d2">Version</label><select id="d2" bind:value={n.digest.version}><option value="manager">Manager: plain words, no IPs</option><option value="technical">Technical</option></select></div></div>
  <div class="row"><button class="btn primary" onclick={saveNotify} disabled={S.saving}>Save notifications</button><button class="btn" onclick={digest}>Send digest now</button></div>
</section>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; align-items: end; }</style>
