// App-wide state (Svelte 5 runes). Simple mode hides Investigate, Coverage, Metrics and Rules (doc 9.3).
export const app = $state({ me: null, advanced: false, health: null, toast: '', tenant: '', tenants: [] });
export const tq = (sep = '&') => (app.tenant && !app.me?.tenant_id ? `${sep}tenant=${app.tenant}` : '');

let t;
export function toast(msg) {
  app.toast = msg;
  clearTimeout(t);
  t = setTimeout(() => (app.toast = ''), 6000);
}

export function setAdvanced(v) {
  app.advanced = v;
  try { localStorage.setItem('sieve.advanced', v ? '1' : '0'); } catch { /* private mode */ }
}

export function loadMode(defaultSimple) {
  try {
    const v = localStorage.getItem('sieve.advanced');
    app.advanced = v === null ? !defaultSimple : v === '1';
  } catch { app.advanced = !defaultSimple; }
}

export const canEdit = () => app.me && app.me.role !== 'viewer';
export const isAdmin = () => app.me && app.me.role === 'admin';
