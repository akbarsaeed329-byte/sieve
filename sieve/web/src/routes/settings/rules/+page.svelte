<script>
  import { onMount } from 'svelte';
  import { get } from '$lib/api.js';
  import { S, save } from '$lib/settings.svelte.js';
  let f = $state({ ...S.s.filter, allow_rule_ids: S.s.filter.allow_rule_ids.join(', '), allow_srcips: S.s.filter.allow_srcips.join(', ') });
  let assets = $state(JSON.parse(JSON.stringify(S.s.assets)));
  let grouping = $state({ ...S.s.grouping }), weights = $state({ ...S.s.weights }), bands = $state({ ...S.s.bands });
  let tw = $state(S.s.tripwire_threshold), shadow = $state(S.s.shadow_mode), flagged = $state([]);
  onMount(async () => { flagged = ((await get('/api/suppressions').catch(() => ({ by_reason: [] }))).by_reason || []).filter((r) => r.flagged); });
  const list = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const saveAll = () => save({ filter: { min_level: Number(f.min_level), allow_rule_ids: list(f.allow_rule_ids), allow_srcips: list(f.allow_srcips) },
    assets: assets.filter((a) => a.agent_name), grouping, weights, bands, tripwire_threshold: Number(tw), shadow_mode: shadow }, 'Rules saved.');
</script>
{#if flagged.length}<div class="banner bad stack" role="alert"><strong>Filters that hid a real alert</strong>
  {#each flagged as r}<span>{r.reason}: {r.restored} restored by reviewers</span>{/each}<span class="small">Tighten or remove these below.</span></div>{/if}
<section class="card pad stack" aria-labelledby="fl"><h2 id="fl">Filtering</h2>
  <div class="grid">
    <div class="field"><label for="f1">Minimum Wazuh level</label><input id="f1" type="number" min="0" max="16" bind:value={f.min_level} />
      <span class="hint">Lower alerts are suppressed with a reason, unless they continue an open incident.</span></div>
    <div class="field"><label for="f2">Always hide these rule IDs</label><input id="f2" type="text" bind:value={f.allow_rule_ids} placeholder="530, 531" /></div>
    <div class="field"><label for="f3">Approved source IPs (e.g. your scanner)</label><input id="f3" type="text" bind:value={f.allow_srcips} /></div>
    <div class="field"><label for="f4">Tripwire threshold</label><input id="f4" type="number" step="0.1" min="0.1" bind:value={tw} /><span class="hint">Tripwire hits are never suppressed.</span></div>
    <label class="row"><input type="checkbox" bind:checked={shadow} /> Shadow mode: triage and record, send no notifications</label>
  </div>
</section>
<section class="card pad stack" aria-labelledby="as"><h2 id="as">Asset criticality</h2>
  <div class="table-wrap"><table><thead><tr><th>Agent name</th><th>Criticality</th><th>Owner</th><th><span class="sr-only">Remove</span></th></tr></thead><tbody>
    {#each assets as a, i}<tr><td><input type="text" aria-label="Agent name" bind:value={a.agent_name} /></td>
      <td><select aria-label="Criticality" bind:value={a.criticality}><option value="critical">Critical</option><option value="normal">Normal</option><option value="test">Test</option></select></td>
      <td><input type="text" aria-label="Owner" bind:value={a.owner} /></td><td><button class="btn small danger" aria-label="Remove {a.agent_name}" onclick={() => assets.splice(i, 1)}>✕</button></td></tr>{/each}
  </tbody></table></div>
  <button class="btn small" style="align-self:flex-start" onclick={() => assets.push({ agent_name: '', criticality: 'normal', owner: '' })}>Add asset</button>
</section>
<section class="card pad stack" aria-labelledby="sc"><h2 id="sc">Grouping and scoring</h2>
  <p class="small muted">S = 50·L/15 + asset + vulnerability + threat intel + chain + first-seen + volume. Tune weights on labelled data; the AI never changes them.</p>
  <div class="grid">
    <div class="field"><label for="g1">Group window (minutes)</label><input id="g1" type="number" min="1" bind:value={grouping.window_minutes} /></div>
    <div class="field"><label for="g2">Maximum incident length (minutes)</label><input id="g2" type="number" min="1" bind:value={grouping.max_minutes} /></div>
    {#each Object.keys(weights) as k}<div class="field"><label for="w-{k}">Weight: {k}</label><input id="w-{k}" type="number" step="0.5" bind:value={weights[k]} /></div>{/each}
    {#each Object.keys(bands) as k}<div class="field"><label for="b-{k}">{k} from score</label><input id="b-{k}" type="number" bind:value={bands[k]} /></div>{/each}
  </div>
</section>
<button class="btn primary" style="align-self:flex-start" disabled={S.saving} onclick={saveAll}>Save rules</button>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; align-items: end; }</style>
