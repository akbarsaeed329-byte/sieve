<script>
  import { S, save } from '$lib/settings.svelte.js';
  let p = $state(JSON.parse(JSON.stringify(S.s.profile)));
  let floors = $state(JSON.parse(JSON.stringify(S.s.floors)));
  const lines = (s) => s.split('\n').map((x) => x.trim()).filter(Boolean);
  const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
</script>
<section class="card pad stack" aria-labelledby="cp"><h2 id="cp">Company profile</h2>
  <p class="muted small">Context only you know. It is given to the AI as trusted context ("gift cards are normal here"), and logins outside business hours are labelled. It never changes severity by itself.</p>
  <div class="grid">
    <div class="field"><label for="o">Organisation</label><input id="o" type="text" bind:value={p.organisation} /></div>
    <div class="field"><label for="i">Industry</label><input id="i" type="text" bind:value={p.industry} placeholder="retail, healthcare, MSP…" /></div>
    <div class="field"><label for="h">Business hours</label><input id="h" type="text" bind:value={p.business_hours} placeholder="08:00-18:00" /></div>
    <div class="field"><label for="tz">Time zone</label><input id="tz" type="text" bind:value={p.timezone} placeholder="Europe/Brussels" /></div>
  </div>
  <fieldset class="row" style="border:none;padding:0"><legend class="small muted">Business days</legend>
    {#each DAYS as d, k}<label class="row small"><input type="checkbox" checked={p.business_days.includes(k)} onchange={(e) => (p.business_days = e.currentTarget.checked ? [...p.business_days, k].sort() : p.business_days.filter((x) => x !== k))} /> {d}</label>{/each}</fieldset>
  <div class="field"><label for="na">Normal activity (one per line)</label><textarea id="na" style="font-family:var(--sans)" value={p.normal_activity.join('\n')} onchange={(e) => (p.normal_activity = lines(e.currentTarget.value))} placeholder="The deploy account runs at 02:00 from 10.0.4.12"></textarea></div>
  <div class="field"><label for="cs">Critical services (one per line)</label><textarea id="cs" style="font-family:var(--sans);min-height:80px" value={p.critical_services.join('\n')} onchange={(e) => (p.critical_services = lines(e.currentTarget.value))}></textarea></div>
  <button class="btn primary" style="align-self:flex-start" disabled={S.saving} onclick={() => save({ profile: p }, 'Profile saved.')}>Save profile</button>
</section>
<section class="card pad stack" aria-labelledby="fl"><h2 id="fl">Severity floors</h2>
  <p class="muted small">Single events that always reach at least a given severity, whatever the score. They appear as an override on the incident.</p>
  <div class="table-wrap"><table><thead><tr><th>On</th><th>Name</th><th>Matches</th><th>At least</th></tr></thead><tbody>
    {#each floors as f}<tr><td><input type="checkbox" aria-label="Enable {f.name}" bind:checked={f.enabled} /></td><td>{f.name}</td>
      <td class="small">{f.min_level != null ? `Wazuh level ≥ ${f.min_level}` : ''}{f.techniques.length ? `ATT&CK ${f.techniques.join(', ')}` : ''}{f.critical_asset_only ? ' on critical assets' : ''}</td>
      <td><select aria-label="Band for {f.name}" bind:value={f.band}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select></td></tr>{/each}</tbody></table></div>
  <button class="btn primary" style="align-self:flex-start" onclick={() => save({ floors }, 'Floors saved.')}>Save floors</button>
</section>
<style>.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; align-items: end; }</style>
