import { get, put } from '$lib/api.js';
import { toast } from '$lib/state.svelte.js';
import { errText } from '$lib/util.js';

export const S = $state({ s: null, secrets: {}, error: null, saving: false });

export async function loadSettings() {
  try { const r = await get('/api/settings'); S.s = r.settings; S.secrets = r.secrets; S.error = null; }
  catch (e) { S.error = e; }
}

export async function save(patch, msg = 'Saved.') {
  S.saving = true;
  try { const r = await put('/api/settings', patch); S.s = r.settings; toast(msg); return true; }
  catch (e) { toast(errText(e)); S.error = e; return false; }
  finally { S.saving = false; }
}

export async function setSecret(name, value) {
  try { await put('/api/secrets', { name, value }); S.secrets[name] = value ? 'stored' : 'unset'; toast(value ? 'Secret stored (encrypted).' : 'Secret cleared.'); }
  catch (e) { toast(errText(e)); }
}

export const secretLabel = (st) => ({ env: 'set by environment variable', stored: 'stored, encrypted', unset: 'not set' })[st] || 'not set';
