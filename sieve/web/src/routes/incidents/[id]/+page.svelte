<script>
  import { onMount, tick } from 'svelte';
  import { page } from '$app/state';
  import { get, post, put } from '$lib/api.js';
  import { app, canEdit, isAdmin, toast } from '$lib/state.svelte.js';
  import { ago, hhmmss, errText, STATUS, until, plural } from '$lib/util.js';
  import Pill from '$c/Pill.svelte';
  import Untrusted from '$c/Untrusted.svelte';
  import ErrorBox from '$c/ErrorBox.svelte';

  let i = $state(null), error = $state(null), busy = $state(false), nis2 = $state(null), shown = $state(20);
  let id = $derived(page.params.id);
  let users = $state([]), note = $state(''), tagText = $state(''), fpOpen = $state(false), fpReason = $state('');
  let sug = $state(null), makeExc = $state(true), excDays = $state(30), mergeInto = $state('');
  let prec = $state(null), viewed = false, comp = $state(null), compOpen = $state(false);
  async function loadComp() { comp = await get(`/api/incidents/${id}/compliance`).catch(() => null); }
  async function setComp(patch, msg) {
    try { comp = { ...(await put(`/api/incidents/${id}/compliance`, patch)), dora_criteria_labels: comp?.dora_criteria_labels, enabled: comp?.enabled }; if (msg) toast(msg); }
    catch (e) { toast(errText(e)); }
  }
  const local = (iso) => { if (!iso) return ''; const d = new Date(iso); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
  function clockText(it) {
    if (it.state === 'sent') return `sent ${new Date(it.sent_at).toLocaleString()}`;
    if (it.minutes_left == null) return '';
    const m = Math.abs(it.minutes_left), t = m < 120 ? `${m} min` : m < 2880 ? `${Math.round(m / 60)} h` : `${Math.round(m / 1440)} d`;
    return it.minutes_left < 0 ? `${t} overdue` : `${t} left`;
  }
  async function download(path, name) {
    const r = await fetch(path, { credentials: 'same-origin' });
    if (!r.ok) { toast('Download failed.'); return; }
    const a = document.createElement('a'); a.href = URL.createObjectURL(await r.blob()); a.download = name; a.click();
  }
  onMount(async () => {
    users = await get('/api/users/directory').catch(() => []);
    prec = await get(`/api/incidents/${id}/precedents`).catch(() => null);
    loadComp();
  });
  // Against overtrust: record that the evidence was actually looked at (needed to close High/Critical).
  async function markViewed() { if (viewed) return; viewed = true; await post(`/api/incidents/${id}/evidence-viewed`).catch(() => { viewed = false; }); }
  $effect(() => {
    if (!i) return;
    const el = document.getElementById('evidence'); if (!el) return;
    let t; const ob = new IntersectionObserver(([e]) => { clearTimeout(t); if (e.isIntersecting) t = setTimeout(markViewed, 2000); }, { threshold: 0.3 });
    ob.observe(el); return () => { ob.disconnect(); clearTimeout(t); };
  });
  async function downloadTrace() {
    const t = await get(`/api/incidents/${id}/trace`);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(t, null, 2)], { type: 'application/json' }));
    a.download = `sieve-INC-${id}-decision-trace.json`; a.click();
  }
  async function openFp() { fpOpen = true; fpReason = ''; sug = await get(`/api/incidents/${id}/exception-suggestion`).catch(() => null); }
  async function submitFp(e) {
    e.preventDefault(); busy = true;
    try {
      await post(`/api/incidents/${id}/false-positive`, { reason: fpReason });
      if (makeExc && sug) {
        await post('/api/exceptions', { rule_id: sug.rule_id, agent_name: sug.agent_name, srcip: sug.srcip, user: sug.user,
          reason: fpReason, expires_in_days: Number(excDays), from_incident: Number(id) });
        toast('Marked false positive. Matching alerts will now be suppressed with your reason.');
      } else toast('Marked false positive.');
      fpOpen = false; await load();
    } catch (err) {
      if (err.code === 'SIEVE-CASE-428') { fpOpen = false; toast('Check the evidence first: it is below. Then mark it.'); document.getElementById('evidence')?.scrollIntoView({ behavior: 'smooth' }); }
      else toast(errText(err));
    } finally { busy = false; }
  }
  async function addNote(e) { e.preventDefault(); if (!note.trim()) return;
    try { await post(`/api/incidents/${id}/comments`, { body: note }); note = ''; await load(); } catch (err) { toast(errText(err)); } }
  async function assignTo(v) { try { await post(`/api/incidents/${id}/assign`, { assignee: v || null }); toast(v ? `Assigned to ${v}.` : 'Unassigned.'); await load(); } catch (err) { toast(errText(err)); } }
  async function saveTags(e) { e.preventDefault();
    try { await post(`/api/incidents/${id}/tags`, { tags: [...(i.tags || []), ...tagText.split(/[\s,]+/)].filter(Boolean) }); tagText = ''; await load(); } catch (err) { toast(errText(err)); } }
  async function dropTag(t) { try { await post(`/api/incidents/${id}/tags`, { tags: i.tags.filter((x) => x !== t) }); await load(); } catch (err) { toast(errText(err)); } }
  async function doMerge(e) { e.preventDefault();
    if (!mergeInto || !confirm(`Merge ${i.ref} into incident #${mergeInto}? Its alerts move there.`)) return;
    try { await post(`/api/incidents/${id}/merge`, { into: Number(mergeInto) }); toast('Merged.'); location.href = `/incidents/${mergeInto}`; } catch (err) { toast(errText(err)); } }
  async function load() {
    try { i = await get(`/api/incidents/${id}`); error = null; } catch (e) { error = e; }
    await tick();
    if (location.hash) document.querySelector(location.hash)?.scrollIntoView();
  }
  onMount(load);

  const act = (path, body, msg) => async () => {
    busy = true;
    try { await post(`/api/incidents/${id}/${path}`, body); toast(msg); await load(); }
    catch (e) {
      if (e.code === 'SIEVE-CASE-428') { toast('Check the evidence first: it is below. Then close the incident.'); document.getElementById('evidence')?.scrollIntoView({ behavior: 'smooth' }); }
      else toast(errText(e));
    } finally { busy = false; }
  };
  async function tickStep(step, checked) {
    try { await post(`/api/incidents/${id}/checklist/${step}`, { checked }); }
    catch (e) { toast(errText(e)); await load(); }
  }
  async function respond(action) {
    const what = action === 'firewall-drop' ? `block ${i.srcip} on ${i.agent_name}` : `lock account ${i.user} on ${i.agent_name}`;
    if (!confirm(`Run Wazuh active response to ${what}? This is logged with your name.`)) return;
    await act(`response/${action}`, { confirm: true }, 'Active response sent to Wazuh.')();
  }
  async function draft() { try { nis2 = await get(`/api/incidents/${id}/nis2-draft`); } catch (e) { toast(errText(e)); } }
  function copy(text) { navigator.clipboard?.writeText(text).then(() => toast('Copied.')); }
  async function exportStix() {
    const b = await get(`/api/incidents/${id}/stix`);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(b, null, 2)], { type: 'application/json' }));
    a.download = `sieve-INC-${id}-stix.json`; a.click();
  }
  function key(e) {
    if (e.target.closest('input, textarea, select') || e.metaKey || e.ctrlKey) return;
    if (e.key.toLowerCase() === 'e') document.getElementById('evidence')?.scrollIntoView();
    if (e.key.toLowerCase() === 'a' && i?.status === 'new' && canEdit()) act('acknowledge', undefined, 'Acknowledged.')();
  }

  let summary = $derived(i?.explanation?.summary?.length ? i.explanation.summary.map((s) => ({ text: s.text, evidence: s.evidence_refs })) : (i?.facts || []));
  let aiUsed = $derived(!!i?.explanation?.summary?.length);
  let evIndex = $derived.by(() => {
    const m = new Map(); let n = 0;
    for (const s of summary) for (const r of s.evidence) if (!m.has(r)) m.set(r, ++n);
    return m;
  });
  let hitAlertIds = $derived(new Set((i?.tripwire_hits || []).map((h) => h.alert_id)));
  let evidenceAlerts = $derived.by(() => {
    if (!i) return [];
    const cited = new Set([...evIndex.keys()].filter((r) => r.startsWith('alert:')));
    return i.alerts.filter((a) => cited.has(a.ref) || hitAlertIds.has(a.id));
  });
  let total = $derived(i ? i.breakdown.reduce((a, b) => a + b.points, 0) : 0);
  let timeline = $derived.by(() => {
    if (!i) return [];
    const a = i.alerts, out = [];
    if (a.length) out.push({ t: a[0].timestamp, text: `First alert: ${a[0].description}` });
    const ok = a.find((x) => x.groups.includes('authentication_success'));
    const fails = a.filter((x) => x.groups.some((g) => g.startsWith('authentication_fail')));
    if (fails.length > 1) out.push({ t: fails[fails.length - 1].timestamp, text: `${fails.length}th failed login` });
    if (ok) out.push({ t: ok.timestamp, text: `Successful login${ok.user ? ' as ' + ok.user : ''}` });
    if (a.length > 1) out.push({ t: a[a.length - 1].timestamp, text: 'Latest alert' });
    if (i.acknowledged_at) out.push({ t: i.acknowledged_at, text: `Acknowledged by ${i.assignee || 'someone'}` });
    if (i.explanation) out.push({ t: i.explanation.created_at, text: 'AI summary added, checked against evidence' });
    if (i.resolved_at) out.push({ t: i.resolved_at, text: STATUS[i.status] });
    return out.sort((x, y) => new Date(x.t) - new Date(y.t));
  });
</script>

<svelte:window onkeydown={key} />
<svelte:head><title>{i ? `INC-${id} ${i.title}` : 'Incident'} · Sieve</title></svelte:head>
<ErrorBox {error} />
{#if i}
<div class="stack-lg">
  <div class="small"><a href="/incidents">Incidents</a><span class="muted"> / {i.ref}</span></div>
  <header class="row between" style="align-items:flex-start">
    <div class="stack" style="gap:10px;flex:1 1 min(520px, 100%);min-width:0">
      <div class="row"><Pill band={i.band} /><span class="small muted">score {i.score}{#if i.status !== 'new'} · {STATUS[i.status]}{/if}</span>
        {#if i.sla_due && i.status === 'new'}{@const u = until(i.sla_due)}<span class="sla" class:late={u.overdue}>SLA {u.text}</span>{/if}
        {#if i.escalated_at}<span class="sla late">escalated</span>{/if}
        {#if i.team}<span class="tag">team: {i.team}</span>{/if}
        {#if i.ticket_ref?.jira}<a class="tag" href={i.ticket_ref.jira_url} target="_blank" rel="noopener noreferrer">Jira {i.ticket_ref.jira}</a>{/if}
        {#each i.tags as t}<span class="tag">{t}{#if canEdit()}<button aria-label="Remove tag {t}" onclick={() => dropTag(t)}>×</button>{/if}</span>{/each}
        {#if i.is_selftest}<span class="small muted">· setup test</span>{/if}</div>
      <h1>{i.title}</h1>
      <dl class="facts">
        <div><dt>Host</dt><dd class="mono">{i.agent_name || '–'}</dd></div>
        <div><dt>Source</dt><dd class="mono">{i.srcip || '–'}</dd></div>
        <div><dt>User</dt><dd class="mono">{i.user || '–'}</dd></div>
        <div><dt>Alerts</dt><dd>{i.alert_count} grouped</dd></div>
        <div><dt>Opened</dt><dd>{hhmmss(i.opened_at)}, {ago(i.opened_at)} ago</dd></div>
        <div><dt>ATT&amp;CK</dt><dd>{#each i.techniques as t, n}<a href="https://attack.mitre.org/techniques/{t.id.replace('.', '/')}/" target="_blank" rel="noopener noreferrer">{t.id} {t.name}</a>{n < i.techniques.length - 1 ? ', ' : ''}{:else}–{/each}</dd></div>
      </dl>
    </div>
    {#if canEdit()}
      <div class="row">
        {#if i.status === 'new'}<button class="btn primary" disabled={busy} onclick={act('acknowledge', undefined, 'Acknowledged.')}>Acknowledge</button>{/if}
        {#if i.status === 'new' || i.status === 'acknowledged'}
          <button class="btn" disabled={busy} onclick={act('resolve', {}, 'Resolved.')}>Resolve</button>
          <button class="btn" disabled={busy} onclick={openFp}>Mark false positive</button>
        {:else}<button class="btn" disabled={busy} onclick={act('reopen', undefined, 'Reopened.')}>Reopen</button>{/if}
      </div>
    {/if}
  </header>

  {#if i.tripwire}
    <div class="banner trip" role="note">
      <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3 2 21h20L12 3z"/><path d="M12 10v5M12 18v.5"/></svg>
      <div class="stack grow" style="gap:4px"><strong>Tripwire: someone tried to steer the AI</strong>
        <span>The {[...new Set(i.tripwire_hits.map((h) => h.field))].join(', ')} field contained instruction-like text ({[...new Set(i.tripwire_hits.flatMap((h) => h.reasons))].join(', ')}). Sieve handled it as data. Severity comes from rules and did not change. MITRE ATLAS AML.T0051.</span></div>
      <a href="#evidence">See the field</a>
    </div>
  {/if}
  {#if i.partial_context}<div class="banner info" role="note">Partial context: {i.context_notes.join(' ')}</div>{/if}
  {#if i.status === 'auto_closed'}<div class="banner info" role="note"><span class="grow">Auto-closed by an approved rule: {i.context_notes.find((n) => n.startsWith('auto-closed')) || ''}</span>
    {#if canEdit()}<button class="btn small" onclick={act('reopen-auto', undefined, 'Reopened. Auto-close is revoked for this rule.')}>Wrong: reopen and revoke</button>{/if}</div>{/if}
  {#if i.correlations?.length}<div class="banner info" role="note">Correlation rule matched: <strong>{i.correlations.map((c) => c.name).join(', ')}</strong>. Severity raised by your team's rule.</div>{/if}
  {#if prec}<div class="banner info prec" role="note"><div class="stack grow" style="gap:6px"><strong>{prec.headline}</strong>
    {#each prec.items.slice(0, 3) as p}<span class="small"><a href="/incidents/{p.id}">#{p.id}</a> {p.status.replace('_', ' ')}{p.closed_by ? ` by ${p.closed_by}` : ''} · {new Date(p.opened_at).toLocaleDateString()} · {p.match}{#if p.note} · “{p.note}”{/if}</span>{/each}</div></div>{/if}
  {#if i.maintenance}<div class="banner info" role="note"><strong>Approved maintenance:</strong> {i.maintenance}. Non-critical notifications were held; the alerts are kept.</div>{/if}
  {#if i.merged_into}<div class="banner info" role="note">This incident was merged into <a href="/incidents/{i.merged_into}">#{i.merged_into}</a>.</div>{/if}
  {#if fpOpen}
    <form class="card pad stack" onsubmit={submitFp} aria-labelledby="fph" style="border-color:var(--brand)">
      <h2 id="fph">Mark as false positive</h2>
      <div class="field"><label for="fpr">Why? (kept in the audit log and shown to reviewers)</label>
        <input id="fpr" type="text" required minlength="3" bind:value={fpReason} placeholder="e.g. Authorised pentest by Acme, contract 42" /></div>
      {#if sug}
        <label class="row"><input type="checkbox" bind:checked={makeExc} /> Also suppress matching alerts in future</label>
        {#if makeExc}<p class="small muted">Scope: rule {sug.rule_id} on {sug.agent_name || 'any host'}{sug.srcip ? ` from ${sug.srcip}` : ''}{sug.user ? ` for ${sug.user}` : ''}. Tripwire hits are never suppressed.</p>
          <div class="field" style="max-width:220px"><label for="exd">Expires after (days)</label><input id="exd" type="number" min="1" max="365" bind:value={excDays} /></div>{/if}
      {/if}
      <div class="row"><button class="btn primary" disabled={busy}>Confirm</button><button type="button" class="btn" onclick={() => (fpOpen = false)}>Cancel</button></div>
    </form>
  {/if}

  <div class="cols">
    <div class="stack-lg" style="flex:3 1 min(520px, 100%);min-width:0">
      <section class="card pad stack" aria-labelledby="sum">
        {#if aiUsed && i.explained_count && i.alert_count > i.explained_count}
          <div class="banner info small" role="note">This summary was written when the incident had {i.explained_count} alerts; it now has {i.alert_count}. The facts below the score are always current.
            {#if canEdit()}<button class="link" onclick={act('explain', undefined, 'Summary refreshed.')}>Refresh now</button>{/if}</div>{/if}
        <div class="row between"><h2 id="sum">What happened</h2>
          <span class="small muted">{aiUsed ? `Written by ${i.explanation.model}, checked against the evidence` : 'Rule-based facts from the evidence'}</span></div>
        <ol class="sum">
          {#each summary as s}<li>{s.text} {#each s.evidence as r}<a href="#ev-{r.replace(':', '-')}" class="ev" onclick={markViewed}>Evidence {evIndex.get(r)}</a> {/each}</li>{/each}
        </ol>
        {#if aiUsed && i.explanation.validation?.summary_sentences_dropped}
          <p class="small muted">{plural(i.explanation.validation.summary_sentences_dropped, 'AI sentence')} {i.explanation.validation.summary_sentences_dropped === 1 ? 'was' : 'were'} dropped because the evidence did not support them.</p>
        {/if}
        <div class="row small">
          {#if i.wazuh_link}<a href={i.wazuh_link} target="_blank" rel="noopener noreferrer">Show this query in Wazuh</a>{:else}<span class="muted">Wazuh query: <code>{i.wazuh_query}</code></span>{/if}
          <button class="link" onclick={() => copy(summary.map((s) => s.text).join(' '))}>Copy summary</button>
          {#if canEdit()}<button class="link" onclick={act('explain', undefined, 'AI summary requested.')}>Ask the AI again</button>{/if}
        </div>
      </section>

      {#if i.band === 'critical' || i.investigation}
        <section class="card pad stack" aria-labelledby="hyp">
          <div class="row between"><h2 id="hyp">Explanations tested</h2>
            <span class="small muted">{i.investigation ? `${i.investigation.steps.length} read-only checks run${i.investigation.budget_hit ? ', step budget reached' : ''}` : 'Not run yet'}</span></div>
          {#if i.investigation?.hypotheses?.length}
            {#each i.investigation.hypotheses as h}
              <div class="hyp {h.status}"><div class="row between"><strong>{h.name}</strong><span class="small">{({supported:'Supported',refuted:'Ruled out',inconclusive:'Not decided'})[h.status]}</span></div>
                <ul>{#each h.evidence as e}<li>{e}</li>{/each}</ul></div>
            {/each}
          {/if}
          {#if i.investigation}
            <details><summary class="small">Checks and their results</summary>
              <ul class="checks">{#each i.investigation.steps as s}<li><strong>{s.question}</strong> {s.count} result{s.count === 1 ? '' : 's'} <span class="muted small">({s.template}, {s.source})</span>
                <details><summary class="small muted">Show query</summary><pre class="log">{s.query}</pre></details></li>{/each}</ul>
            </details>
          {/if}
          {#if canEdit() && i.band === 'critical'}<button class="btn small" disabled={busy} onclick={act('investigate', undefined, 'Investigation finished.')}>Run checks again</button>{/if}
        </section>
      {/if}

      <section class="card pad stack" aria-labelledby="why">
        <h2 id="why">Why it is {i.band}</h2>
        <table><tbody>
          {#each i.breakdown as b}<tr><td>{b.label}</td><td class="num">+{Math.round(b.points)}</td></tr>{/each}
          <tr><td><strong>Score</strong>{#each i.overrides as o}<br /><span class="small">Override: {o}</span>{/each}</td><td class="num"><strong>{Math.round(total > 100 ? 100 : total)}</strong></td></tr>
        </tbody></table>
        <p class="small muted">Bands: 80+ critical, 60+ high, 40+ medium. Weights are set in Settings › Rules. The AI never changes this.</p>
      </section>
    </div>

    <div class="stack-lg" style="flex:2 1 min(360px, 100%);min-width:0">
      {#if i.playbook}
      <section class="card pad stack" aria-labelledby="todo">
        <h2 id="todo">What to do now</h2>
        {#each i.playbook.steps as s}
          <label class="step"><input type="checkbox" checked={i.checked_steps.includes(s.id)} disabled={!canEdit()}
              onchange={(e) => tickStep(s.id, e.currentTarget.checked)} />
            <span class="stack" style="gap:2px"><span>{s.title}</span><span class="small muted">{s.detail}</span>
              {#if s.requires_approval}<span class="small" style="color:var(--amber-text)">Runs only after you approve it</span>{/if}
              {#if s.active_response && isAdmin() && i.active_response_enabled}
                <button class="btn small danger" type="button" onclick={() => respond(s.active_response)}>Run via Wazuh…</button>{/if}
            </span></label>
        {/each}
        <span class="small muted">From playbook {i.playbook.id}, written by your team. Your ticks are saved for you.</span>
      </section>
      {/if}

      <section class="card pad stack" id="evidence" aria-labelledby="evh">
        <h2 id="evh">Evidence</h2>
        {#each [...evIndex.entries()] as [ref, n]}
          {#if ref.startsWith('alert:')}
            {@const a = i.alerts.find((x) => x.ref === ref)}
            {#if a}<div class="ev-item" id="ev-{ref.replace(':', '-')}"><span class="small" style="font-weight:600">{n}. {a.description} · {hhmmss(a.timestamp)}</span>
              <pre class="log">{a.full_log}</pre>
              {#each Object.entries(a.untrusted).filter(([k]) => k !== 'full_log') as [k, v]}<Untrusted field={k} value={v} hit={hitAlertIds.has(a.id) && i.tripwire_hits.some((h) => h.field === k)} />{/each}</div>{/if}
          {:else}
            <div class="ev-item" id="ev-{ref.replace(':', '-')}"><span class="small" style="font-weight:600">{n}. Context</span>
              <span class="small">{({'context:intel': i.intel ? `${i.intel.source}${i.intel.abuse_score != null ? `, confidence ${i.intel.abuse_score}%` : ''}${i.intel.cached ? ' (cached)' : ''}` : 'Threat-intel list',
                'context:baseline': `Login baseline for ${i.user || 'this account'}, last 14 days.`, 'context:tripwire': 'Tripwire rules (see the untrusted field below).',
                'context:partial': i.context_notes.join(' ')})[ref]}</span></div>
          {/if}
        {/each}
        {#each evidenceAlerts.filter((a) => !evIndex.has(a.ref)) as a}
          <div class="ev-item"><span class="small" style="font-weight:600">Tripwire alert · {hhmmss(a.timestamp)}</span><pre class="log">{a.full_log}</pre>
            {#each Object.entries(a.untrusted) as [k, v]}<Untrusted field={k} value={v} hit={i.tripwire_hits.some((h) => h.field === k)} />{/each}</div>
        {/each}
        <details ontoggle={markViewed}><summary class="small">Open all {i.alert_count} log lines</summary>
          {#each i.alerts.slice(0, shown) as a}<pre class="log" style="margin-top:6px">{hhmmss(a.timestamp)}  {a.full_log}</pre>{/each}
          {#if shown < i.alerts.length}<button class="link small" onclick={() => (shown += 50)}>Show more</button>{/if}
          {#if i.alerts_truncated}<p class="small muted">{i.alerts_truncated} older lines are in Wazuh.</p>{/if}
        </details>
      </section>

      <section class="card pad stack" aria-labelledby="own"><h2 id="own">Owner and notes</h2>
        <div class="row">
          <div class="field grow"><label for="asg">Owner</label>
            <select id="asg" disabled={!canEdit()} value={i.assignee || ''} onchange={(e) => assignTo(e.currentTarget.value)}>
              <option value="">Unassigned</option>{#each users as u}<option value={u.username}>{u.username}</option>{/each}</select></div>
          {#if canEdit()}<form class="field grow" onsubmit={saveTags}><label for="tg">Add tags</label><input id="tg" type="text" placeholder="pci, customer-x" bind:value={tagText} /></form>{/if}
        </div>
        <ol class="notes">{#each i.comments as c}<li><span class="small muted">{c.author} · {new Date(c.at).toLocaleString()}</span><p>{c.body}</p></li>{:else}<li class="small muted">No notes yet.</li>{/each}</ol>
        {#if canEdit()}<form class="stack" onsubmit={addNote}><label class="sr-only" for="nt">Add a note</label>
          <textarea id="nt" style="min-height:70px;font-family:var(--sans)" placeholder="What did you check? Who did you call?" bind:value={note}></textarea>
          <button class="btn small" style="align-self:flex-start">Add note</button></form>
          {#if i.status === 'new' || i.status === 'acknowledged'}
            <form class="row" onsubmit={doMerge}><div class="field"><label for="mg">Merge into incident #</label><input id="mg" type="number" min="1" bind:value={mergeInto} style="max-width:140px" /></div>
              <button class="btn small" style="align-self:flex-end">Merge</button></form>{/if}{/if}
      </section>

      <section class="card pad stack" aria-labelledby="tl"><h2 id="tl">Timeline</h2>
        <ol class="tl">{#each timeline as e}<li><span class="mono small muted">{hhmmss(e.t)}</span><span>{e.text}</span></li>{/each}</ol></section>

      {#if comp && Object.keys(comp.regimes || {}).length}
      <section class="card pad stack" aria-labelledby="regh"><div class="row between"><h2 id="regh">Regulatory clocks</h2>
          <button class="link small" onclick={() => (compOpen = !compOpen)}>{compOpen ? 'Hide details' : 'Assess and record'}</button></div>
        {#each Object.entries(comp.regimes) as [reg, items]}
          <div class="stack" style="gap:6px"><strong class="small">{reg.toUpperCase()}</strong>
            {#each items as it}<div class="clock {it.state}"><span class="grow">{it.name}</span><span class="small">{clockText(it)}</span>
              {#if canEdit() && it.state !== 'sent' && it.name !== 'Classify the incident (major or not)'}
                <button class="btn small" onclick={() => setComp({ mark_sent: `${reg}_${{ 'Early warning': 'early', 'Incident notification': 'notification', 'Final report': 'final', 'Initial notification': 'initial', 'Intermediate report': 'intermediate', 'Notify the data protection authority': 'dpa' }[it.name]}_sent` }, 'Recorded as sent.')}>Mark sent</button>{/if}</div>
              {#if it.hint}<span class="small muted">{it.hint}</span>{/if}{/each}</div>
        {/each}
        {#if compOpen && canEdit()}
          <div class="field"><label for="aw">We became aware at</label><input id="aw" type="datetime-local" value={local(comp.aware_at)} onchange={(e) => setComp({ aware_at: new Date(e.currentTarget.value).toISOString() }, 'Awareness time saved.')} /></div>
          {#if comp.enabled?.dora}
            <fieldset class="stack" style="border:1px solid var(--line);border-radius:8px;padding:12px"><legend class="small">DORA classification (RTS 2024/1772)</legend>
              {#each Object.entries(comp.dora_criteria_labels || {}) as [k, label]}<label class="row small"><input type="checkbox" checked={!!comp.record?.dora_criteria?.[k]}
                onchange={(e) => setComp({ dora_criteria: { ...(comp.record?.dora_criteria || {}), [k]: e.currentTarget.checked } })} /> {label}</label>{/each}
              <label class="row small"><input type="checkbox" checked={!!comp.record?.dora_malicious_loss} onchange={(e) => setComp({ dora_malicious_loss: e.currentTarget.checked })} /> Malicious unauthorised access with data loss</label>
              {#if comp.dora_assessment}<p class="small {comp.dora_assessment.suggest_major ? 'error' : 'muted'}"><strong>{comp.dora_assessment.suggest_major ? 'Likely major' : 'Probably not major'}:</strong> {comp.dora_assessment.reason}. {comp.dora_assessment.note}</p>{/if}
              {#if !comp.record?.dora_classified_major_at}<button class="btn small danger" style="align-self:flex-start" onclick={() => setComp({ dora_classified_major_at: new Date().toISOString() }, 'Classified as major: the 4-hour clock started.')}>We classify this as major (starts the 4-hour clock)</button>{/if}
            </fieldset>{/if}
          {#if comp.enabled?.gdpr}<label class="row small"><input type="checkbox" checked={!!comp.record?.personal_data} onchange={(e) => setComp({ personal_data: e.currentTarget.checked })} /> Personal data was involved (GDPR 72-hour clock)</label>{/if}
          <p class="small muted">Sieve calculates deadlines and drafts text. Classification and filing are your decisions; every change is recorded.</p>
        {/if}
      </section>
      {/if}

      <section class="card pad stack" aria-labelledby="more"><h2 id="more">Share and report</h2>
        <div class="row">
          {#if canEdit()}<button class="btn small" onclick={draft}>Draft NIS2 early warning</button>{/if}
          <button class="btn small" onclick={exportStix}>Export STIX 2.1</button>
          <button class="btn small" onclick={downloadTrace}>Decision trace (audit)</button>
          <button class="btn small" onclick={() => download(`/api/incidents/${id}/report.md`, `sieve-INC-${id}-report.md`)}>Investigation report</button>
          {#if canEdit()}<button class="btn small" onclick={() => download(`/api/incidents/${id}/evidence-pack`, `sieve-INC-${id}-evidence.zip`)}>Evidence pack (sealed)</button>{/if}
          {#if app.advanced}<a class="btn small" href="/investigate?incident={i.id}">Entity graph</a>{/if}
        </div>
        {#if nis2}
          <div class="banner trip small" role="note">{nis2.label}</div>
          <dl class="facts"><div><dt>Early warning due</dt><dd>{new Date(nis2.reporting_deadline).toLocaleString()}</dd></div>
            <div><dt>Notification due</dt><dd>{new Date(nis2.notification_deadline).toLocaleString()}</dd></div>
            <div><dt>Final report due</dt><dd>{new Date(nis2.final_report_deadline).toLocaleDateString()}</dd></div></dl>
          <textarea aria-label="NIS2 draft text" value={nis2.draft_text}></textarea>
          <span class="small muted">Drafted by {nis2.draft_source}. Sieve never sends this to the CCB.</span>
        {/if}
      </section>
    </div>
  </div>
</div>
{/if}
<style>
  .cols { display: flex; flex-wrap: wrap; gap: 24px; align-items: flex-start; }
  .cols > * { min-width: 0; max-width: 100%; }
  .facts { display: flex; flex-wrap: wrap; gap: 8px 28px; margin: 0; }
  .facts div { display: flex; flex-direction: column; gap: 2px; }
  dt { font-size: 13px; color: var(--muted); }
  dd { margin: 0; }
  .sum { margin: 0; padding-left: 20px; display: flex; flex-direction: column; gap: 8px; font-size: 15px; }
  .ev { font-size: 12px; padding: 1px 6px; border-radius: 6px; background: var(--neutral-bg); text-decoration: none; white-space: nowrap; }
  .link { background: none; border: none; padding: 0; color: var(--brand); text-decoration: underline; cursor: pointer; font: inherit; min-height: 24px; }
  .hyp { padding: 12px; border-radius: 8px; border: 1px solid var(--line); }
  .hyp.supported { border-color: var(--crit-bd); background: var(--crit-bg); }
  .hyp.refuted { opacity: 0.85; }
  .hyp ul, .checks { margin: 6px 0 0; padding-left: 18px; }
  .step { display: flex; gap: 10px; align-items: flex-start; min-height: 44px; }
  .ev-item { display: flex; flex-direction: column; gap: 6px; padding-top: 10px; border-top: 1px solid var(--line-2); scroll-margin-top: 16px; }
  .ev-item:target { outline: 2px solid var(--brand); outline-offset: 4px; border-radius: 4px; }
  .tl { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .tl li { display: flex; gap: 12px; }
  .sla { font-size: 12px; padding: 2px 8px; border-radius: 999px; background: var(--neutral-bg); color: var(--soft); }
  .sla.late { background: var(--crit-bg); color: var(--crit); font-weight: 600; }
  .tag { font-size: 12px; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--line); background: var(--card); }
  .tag button { border: none; background: none; cursor: pointer; color: var(--muted); padding: 0 0 0 4px; }
  .clock { display: flex; gap: 10px; align-items: center; padding: 8px 10px; border-radius: 8px; border: 1px solid var(--line); flex-wrap: wrap; }
  .clock.overdue { background: var(--crit-bg); border-color: var(--crit-bd); color: var(--crit); }
  .clock.sent { opacity: 0.7; }
  .prec { background: var(--card); color: var(--ink); border: 1px solid var(--line); }
  .notes { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  .notes li { border-left: 3px solid var(--line); padding-left: 10px; }
</style>
