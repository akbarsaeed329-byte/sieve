<script>
  import { onMount } from 'svelte';
  import { del, get, post } from '$lib/api.js';
  import { toast } from '$lib/state.svelte.js';
  import { errText } from '$lib/util.js';
  let rules = $state([]), test = $state(null);
  const blank = () => ({ name: '', f_rules: '', f_groups: '', f_tech: '', f_min: 1, t_rules: '', t_groups: '', t_tech: '', same: ['srcip'], within_minutes: 10, band: 'high' });
  let r = $state(blank());
  const load = async () => (rules = await get('/api/correlation-rules'));
  onMount(load);
  const L = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const body = () => ({ name: r.name, first: { rule_ids: L(r.f_rules), groups: L(r.f_groups), techniques: L(r.f_tech), min_count: Number(r.f_min) },
    then: { rule_ids: L(r.t_rules), groups: L(r.t_groups), techniques: L(r.t_tech) }, same: r.same, within_minutes: Number(r.within_minutes), band: r.band });
  async function dry() { try { test = await post('/api/correlation-rules/test', body()); } catch (e) { toast(errText(e)); } }
  async function save(e) { e.preventDefault(); try { await post('/api/correlation-rules', body()); toast('Rule saved. It applies to new alerts.'); r = blank(); test = null; load(); } catch (err) { toast(errText(err)); } }
  const toggleSame = (k, on) => (r.same = on ? [...new Set([...r.same, k])] : r.same.filter((x) => x !== k));
</script>
<section class="card pad stack" aria-labelledby="cr"><h2 id="cr">New correlation rule</h2>
  <p class="muted small">"When <strong>this</strong> happens, then <strong>that</strong> happens, on the same entity, within N minutes, the incident is at least this severe." Test it on the last 30 days before saving.</p>
  <form class="stack" onsubmit={save}>
    <div class="field"><label for="n">Name</label><input id="n" type="text" required minlength="3" bind:value={r.name} placeholder="Port scan, then exploit attempt from the same IP" /></div>
    <fieldset class="grid step"><legend>First</legend>
      <div class="field"><label for="fr">Rule IDs</label><input id="fr" type="text" bind:value={r.f_rules} placeholder="5716, 5720" /></div>
      <div class="field"><label for="fg">or rule groups</label><input id="fg" type="text" bind:value={r.f_groups} placeholder="web_scan" /></div>
      <div class="field"><label for="ft">or ATT&amp;CK techniques</label><input id="ft" type="text" bind:value={r.f_tech} placeholder="T1595" /></div>
      <div class="field"><label for="fm">At least (times)</label><input id="fm" type="number" min="1" bind:value={r.f_min} /></div></fieldset>
    <fieldset class="grid step"><legend>Then</legend>
      <div class="field"><label for="tr">Rule IDs</label><input id="tr" type="text" bind:value={r.t_rules} placeholder="31106" /></div>
      <div class="field"><label for="tg2">or rule groups</label><input id="tg2" type="text" bind:value={r.t_groups} /></div>
      <div class="field"><label for="tt">or ATT&amp;CK techniques</label><input id="tt" type="text" bind:value={r.t_tech} placeholder="T1190" /></div></fieldset>
    <div class="row">
      <fieldset class="row" style="border:none;padding:0"><legend class="small muted">Same</legend>
        {#each [['srcip', 'source IP'], ['user', 'user'], ['agent_name', 'host']] as [k, l]}<label class="row small"><input type="checkbox" checked={r.same.includes(k)} onchange={(e) => toggleSame(k, e.currentTarget.checked)} /> {l}</label>{/each}</fieldset>
      <div class="field"><label for="w">Within (minutes)</label><input id="w" type="number" min="1" max="1440" bind:value={r.within_minutes} /></div>
      <div class="field"><label for="bd">Severity at least</label><select id="bd" bind:value={r.band}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select></div>
    </div>
    {#if test}<p class="small {test.would_fire ? 'ok-text' : 'muted'}">In the last {test.days} days this rule would have fired {test.would_fire} time(s){test.incidents.length ? `, on incidents ${test.incidents.slice(0, 8).map((x) => '#' + x).join(', ')}` : ''}.</p>{/if}
    <div class="row"><button type="button" class="btn" onclick={dry}>Test on last 30 days</button><button class="btn primary">Save rule</button></div>
  </form>
</section>
<div class="card table-wrap"><table><thead><tr><th>Rule</th><th>Logic</th><th>Severity</th><th class="num">Fired</th><th></th></tr></thead><tbody>
  {#each rules as x}<tr class:muted={!x.enabled}><td>{x.name}<br /><span class="small muted">by {x.created_by}</span></td>
    <td class="small mono">{JSON.stringify(x.first)} → {JSON.stringify(x.then)}<br />same {x.same.join(' + ')} within {x.within_minutes} min</td><td>{x.band}</td><td class="num">{x.hits}</td>
    <td>{#if x.enabled}<button class="btn small" onclick={async () => { await del(`/api/correlation-rules/${x.id}`).catch((e) => toast(errText(e))); load(); }}>Disable</button>{:else}disabled{/if}</td></tr>
  {:else}<tr><td colspan="5" class="empty">No correlation rules yet.</td></tr>{/each}</tbody></table></div>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; align-items: end; }
  .step { border: 1px solid var(--line); border-radius: 8px; padding: 12px; } legend { font-weight: 600; padding: 0 6px; }</style>
