// API client. Same-origin only; sends the CSRF token on every state-changing request.
// Errors are always { code, message, fix } so the UI can show the fix next to the problem.
function csrf() {
  const m = document.cookie.match(/(?:^|; )sieve_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

export async function api(path, { method = 'GET', body } = {}) {
  const init = { method, credentials: 'same-origin', headers: { accept: 'application/json' } };
  if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  if (method !== 'GET') init.headers['x-sieve-csrf'] = csrf();
  let r;
  try {
    r = await fetch(path, init);
  } catch {
    throw { code: 'SIEVE-NET-000', message: 'Cannot reach Sieve.', fix: 'Check that Sieve is running, then reload.' };
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401 && !path.startsWith('/api/auth/') && !path.startsWith('/api/setup')) {
      window.dispatchEvent(new CustomEvent('sieve:signed-out'));
    }
    throw data.code ? data : { code: `HTTP ${r.status}`, message: 'Request failed.', fix: '' };
  }
  return data;
}

export const get = (p) => api(p);
export const post = (p, body) => api(p, { method: 'POST', body: body ?? {} });
export const put = (p, body) => api(p, { method: 'PUT', body });
