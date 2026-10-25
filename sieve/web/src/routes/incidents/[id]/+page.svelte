<script>
  import { onMount, tick } from 'svelte';
  import { page } from '$app/state';
  import { get, post } from '$lib/api.js';
  import { app, canEdit, isAdmin, toast } from '$lib/state.svelte.js';
  import { ago, hhmmss, errText, STATUS, until, plural } from '$lib/util.js';
  import Pill from '$c/Pill.svelte';
  import Untrusted from '$c/Untrusted.svelte';
  import ErrorBox from '$c/ErrorBox.svelte';

  let i = $state(null), error = $state(null), busy = $state(false), nis2 = $state(null), shown = $state(20);
  let id = $derived(page.params.id);
  let users = $state([]), note = $state(''), tagText = $state(''), fpOpen = $state(false), fpReason = $state('');
  let sug = $state(null), makeExc = $state(true), excDays = $state(30), mergeInto = $state('');
  onMount(async () => { users = await get('/api/users/directory').catch(() => []); });
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
    } catch (err) { toast(errText(err)); } finally { busy = false; }
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
    catch (e) { toast(errText(e)); } finally { busy = false; }
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
        <div class="row between"><h2 id="sum">What happened</h2>
          <span class="small muted">{aiUsed ? `Written by ${i.explanation.model}, checked against the evidence` : 'Rule-based facts from the evidence'}</span></div>
        <ol class="sum">
          {#each summary as s}<li>{s.text} {#each s.evidence as r}<a href="#ev-{r.replace(':', '-')}" class="ev">Evidence {evIndex.get(r)}</a> {/each}</li>{/each}
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
        <details><summary class="small">Open all {i.alert_count} log lines</summary>
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

      <section class="card pad stack" aria-labelledby="more"><h2 id="more">Share and report</h2>
        <div class="row">
          {#if canEdit()}<button class="btn small" onclick={draft}>Draft NIS2 early warning</button>{/if}
          <button class="btn small" onclick={exportStix}>Export STIX 2.1</button>
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
  .notes { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  .notes li { border-left: 3px solid var(--line); padding-left: 10px; }
</style>
