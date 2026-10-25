export const BAND = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
export const STATUS = { new: 'New', acknowledged: 'Acknowledged', resolved: 'Resolved', false_positive: 'False positive', merged: 'Merged', auto_closed: 'Auto-closed' };

export function until(iso) {
  if (!iso) return null;
  const m = Math.round((new Date(iso).getTime() - Date.now()) / 60000);
  const abs = Math.abs(m), t = abs < 90 ? `${abs} min` : abs < 2880 ? `${Math.round(abs / 60)} h` : `${Math.round(abs / 1440)} d`;
  return { overdue: m < 0, text: m < 0 ? `${t} overdue` : `due in ${t}` };
}

export function ago(iso) {
  if (!iso) return '';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return `${Math.round(s)} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} d`;
}

export function hhmmss(iso) {
  return iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
}

export function errText(e) {
  if (!e) return '';
  return `${e.message || e}${e.fix ? ' ' + e.fix : ''}${e.code ? ` (${e.code})` : ''}`;
}

export const fmt = (n) => (n === null || n === undefined ? '–' : Number(n).toLocaleString());

export const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;
