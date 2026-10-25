<script>
  import { get, post } from '$lib/api.js';
  import { app, toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  import { S, save } from '$lib/settings.svelte.js';
  let setup = $state(null), code = $state(''), pw = $state('');
  let ret = $state({ ...(S.s?.retention || {}) }), req = $state(!!S.s?.require_2fa_for_admins), sla = $state({ ...(S.s?.sla || {}) });
  let oidc = $state({ ...(S.s?.oidc || {}) }), evrev = $state(S.s?.require_evidence_review ?? true);
  const L = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  import Secret from '$c/Secret.svelte';
  async function start() { try { setup = await post('/api/auth/2fa/setup'); } catch (e) { toast(errText(e)); } }
  async function enable(e) { e.preventDefault(); try { await post('/api/auth/2fa/enable', { code }); toast('Two-factor sign-in is on.'); setup = null; code = ''; app.me = await get('/api/auth/me'); } catch (err) { toast(errText(err)); } }
  async function disable(e) { e.preventDefault(); try { await post('/api/auth/2fa/disable', { code, password: pw }); toast('Two-factor sign-in is off.'); code = pw = ''; app.me = await get('/api/auth/me'); } catch (err) { toast(errText(err)); } }
</script>
{#if app.me?.must_enroll_2fa}<div class="banner bad" role="alert">This server requires admins to use two-factor sign-in. Turn it on below to continue.</div>{/if}
<section class="card pad stack" aria-labelledby="tf"><h2 id="tf">Your two-factor sign-in</h2>
  {#if app.me?.totp_enabled}
    <p class="ok-text">On. You need a code from your authenticator app at each sign-in.</p>
    <form class="row" onsubmit={disable}><div class="field"><label for="p">Password</label><input id="p" type="password" autocomplete="current-password" bind:value={pw} required /></div>
      <div class="field"><label for="c">Current code</label><input id="c" type="text" inputmode="numeric" maxlength="8" bind:value={code} required /></div>
      <button class="btn danger" style="align-self:flex-end">Turn off</button></form>
  {:else if setup}
    <ol class="stack" style="padding-left:20px"><li>Open an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Aegis…).</li>
      <li>Add an account by key: <code style="user-select:all;word-break:break-all">{setup.secret}</code> (time-based, 6 digits), or open <a href={setup.uri}>this link</a> on the phone.</li>
      <li>Enter the code it shows.</li></ol>
    <form class="row" onsubmit={enable}><div class="field"><label for="c2">6-digit code</label><input id="c2" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="8" bind:value={code} required /></div>
      <button class="btn primary" style="align-self:flex-end">Turn on</button></form>
  {:else}<p class="muted">Protect your account with a code from your phone in addition to your password.</p>
    <button class="btn primary" style="align-self:flex-start" onclick={start}>Set up two-factor sign-in</button>{/if}
</section>
{#if app.me?.role === 'admin'}
<section class="card pad stack" aria-labelledby="pol"><h2 id="pol">Policy</h2>
  <label class="row"><input type="checkbox" bind:checked={req} /> Require two-factor sign-in for all admins</label>
  <div class="grid">
    <div class="field"><label for="r1">Keep raw alerts and suppressions (days)</label><input id="r1" type="number" min="1" bind:value={ret.alerts_days} /><span class="hint">Incidents, notes and the audit log are kept.</span></div>
    <div class="field"><label for="r2">Keep AI call records (days)</label><input id="r2" type="number" min="1" bind:value={ret.llm_calls_days} /></div>
  </div>
  <h3>Time to acknowledge (SLA, minutes)</h3>
  <div class="grid">{#each ['critical', 'high', 'medium', 'low'] as b}<div class="field"><label for="s-{b}">{b}</label><input id="s-{b}" type="number" min="1" bind:value={sla[b]} /></div>{/each}
    <label class="row"><input type="checkbox" bind:checked={sla.escalate} /> Send one escalation message when a high or critical incident passes its SLA unacknowledged</label></div>
  <label class="row"><input type="checkbox" bind:checked={evrev} /> Require opening the evidence before closing high and critical incidents</label>
  <button class="btn primary" style="align-self:flex-start" onclick={() => save({ require_2fa_for_admins: req, retention: ret, sla, require_evidence_review: evrev }, 'Security policy saved.')}>Save policy</button>
  <p class="small muted">Backups: run <code>sieve backup /path/sieve-backup.db</code> (safe while running) and keep <code>data/.secret_key</code> with it.</p>
</section>
{/if}
{#if app.me?.role === 'admin'}
<section class="card pad stack" aria-labelledby="sso"><h2 id="sso">Single sign-on (OIDC)</h2>
  <p class="muted small">Works with Microsoft Entra ID, Google, Okta and Keycloak. Register Sieve as a web app with redirect URI <code>{S.s.notify.public_url}/api/auth/oidc/callback</code>. Roles come from group membership; users are created on first sign-in.</p>
  <div class="grid"><label class="row"><input type="checkbox" bind:checked={oidc.enabled} /> Enabled</label>
    <div class="field"><label for="oi">Issuer URL</label><input id="oi" type="url" bind:value={oidc.issuer} placeholder="https://login.microsoftonline.com/<tenant>/v2.0" /></div>
    <div class="field"><label for="oc">Client ID</label><input id="oc" type="text" bind:value={oidc.client_id} /></div>
    <Secret name={oidc.client_secret_env} label="Client secret" />
    <div class="field"><label for="og">Groups claim</label><input id="og" type="text" bind:value={oidc.groups_claim} /></div>
    <div class="field"><label for="oa">Admin groups</label><input id="oa" type="text" value={(oidc.admin_groups || []).join(', ')} onchange={(e) => (oidc.admin_groups = L(e.currentTarget.value))} /></div>
    <div class="field"><label for="on">Analyst groups</label><input id="on" type="text" value={(oidc.analyst_groups || []).join(', ')} onchange={(e) => (oidc.analyst_groups = L(e.currentTarget.value))} /></div>
    <div class="field"><label for="od">Everyone else</label><select id="od" bind:value={oidc.default_role}><option value="none">No access</option><option value="viewer">Viewer</option><option value="analyst">Analyst</option></select></div></div>
  <button class="btn primary" style="align-self:flex-start" onclick={() => save({ oidc }, 'Single sign-on saved.')}>Save SSO</button>
</section>
{/if}
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; align-items: end; }</style>
