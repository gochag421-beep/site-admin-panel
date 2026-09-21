const crypto = require('node:crypto');
function redact(value) {
  return String(value ?? '').replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, '[PRIVATE KEY REDACTED]')
    .replace(/\b(?:sk-(?:or-v1-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b/g, '[SECRET REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[JWT REDACTED]')
    .replace(/\b(authorization|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]');
}
function safeUrl(input) {
  try { const u = new URL(input); u.username=''; u.password=''; u.hash='';
    for (const key of [...u.searchParams.keys()]) u.searchParams.set(key,'REDACTED');
    return redact(u.href);
  } catch { return redact(input); }
}
function safeText(input) {
  return redact(String(input ?? '').replace(/https?:\/\/[^\s<>"']+/g, s=>safeUrl(s))).slice(0,2000);
}
function sanitize(value, key='') {
  if (typeof value === 'string') return /url|target/i.test(key) ? safeUrl(value) : safeText(value);
  if (Array.isArray(value)) return value.map(v=>sanitize(v,key));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,sanitize(v,k)]));
  return value;
}
const hash = value => crypto.createHash('sha256').update(value).digest('hex').slice(0,24);
module.exports={redact,safeText,safeUrl,sanitize,hash};
