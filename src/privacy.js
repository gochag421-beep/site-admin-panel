function safeUrl(value) {
  try {
    const url = new URL(value); url.username = ''; url.password = ''; url.hash = '';
    for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, '[redacted]');
    return url.href;
  } catch { return '[invalid URL]'; }
}
function safeText(value) {
  return String(value ?? '').replace(/https?:\/\/[^\s<>"']+/gi, safeUrl)
    .replace(/\bsk-(?:or-v1-)?[a-zA-Z0-9_-]{8,}\b/g, '[redacted]')
    .replace(/\b(Bearer\s+)\S+/gi, '$1[redacted]')
    .replace(/\b([\w-]*(?:token|secret|password|api_key|session)[\w-]*\s*[=:]\s*)[^\s;,]+/gi, '$1[redacted]').slice(0, 1000);
}
function aiPayload(report) {
  return { target: safeUrl(report.target), status: report.status, coverage: report.coverage, summary: report.summary,
    findings: report.findings.slice(0, 100).map(f => ({ severity: f.severity, title: safeText(f.title), evidence: safeText(f.evidence), recommendation: safeText(f.recommendation), url: safeUrl(f.url) })),
    omittedFindings: Math.max(0, report.findings.length - 100) };
}
module.exports = { safeUrl, safeText, aiPayload };
