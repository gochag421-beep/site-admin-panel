const cheerio = require('cheerio');
const { createHash } = require('node:crypto');
const { parseUrl, validatePublicUrl, requestPage, delay } = require('./network');
const { safeUrl, safeText } = require('./privacy');
const severityWeight = { critical: 10, high: 7, medium: 4, low: 1, info: 0 };

function finding(severity, title, evidence, recommendation, url) {
  return { id: createHash('sha256').update(title + '|' + url + '|' + evidence).digest('hex').slice(0, 16),
    severity, title, evidence: safeText(evidence), recommendation, url: safeUrl(url), confidence: 'configuration-check' };
}
function inspectPage(url, response, html, findings) {
  const add = (s, t, e, r) => findings.push(finding(s, t, e, r, url));
  const h = response.headers;
  const secure = new URL(url).protocol === 'https:';
  const isHtml = /text\/html|application\/xhtml\+xml/i.test(h.get('content-type') || '');
  if (isHtml) {
    const csp = h.get('content-security-policy');
    if (!csp) add('medium', 'Απουσία Content Security Policy', 'Δεν υπάρχει CSP response header. Τυχόν meta policy δεν αξιολογήθηκε.', 'Πρόσθεσε CSP μετά από δοκιμή σε report-only mode.');
    else if (!/(?:^|;)\s*(?:default-src|script-src)\s/i.test(csp) || /(?:^|;)\s*(?:default-src|script-src)[^;]*(?:'unsafe-inline'|'unsafe-eval'|\*)/i.test(csp)) add('low', 'CSP χρειάζεται έλεγχο', 'Ευρείες πηγές ή απουσία περιορισμού scripts. Δεν αποδεικνύεται XSS.', 'Έλεγξε directives, nonces και hashes πριν περιορίσεις την πολιτική.');
    if (h.get('x-content-type-options')?.toLowerCase() !== 'nosniff') add('low', 'MIME sniffing protection λείπει ή είναι άκυρο', 'Αναμένεται X-Content-Type-Options: nosniff.', 'Όρισε X-Content-Type-Options: nosniff.');
    if (!h.get('referrer-policy')) add('low', 'Απουσία Referrer Policy', 'Δεν υπάρχει Referrer-Policy header.', 'Όρισε strict-origin-when-cross-origin ή αυστηρότερη κατάλληλη πολιτική.');
    if (!h.get('permissions-policy')) add('info', 'Απουσία Permissions Policy', 'Δεν δηλώνονται περιορισμοί δυνατοτήτων browser.', 'Απενεργοποίησε δυνατότητες που δεν χρειάζονται.');
  }
  if (secure && !/\bmax-age\s*=\s*[1-9]\d*/i.test(h.get('strict-transport-security') || '')) add('medium', 'HSTS λείπει ή είναι ανενεργό', 'Δεν βρέθηκε θετικό max-age.', 'Ρύθμισε HSTS αφού επιβεβαιώσεις σωστή λειτουργία HTTPS.');
  if (h.get('server')) add('info', 'Αποκάλυψη server header', 'Ο server δημοσιεύει πληροφορίες λογισμικού.', 'Αφαίρεσε περιττές πληροφορίες εκδόσεων.');
  if (h.get('access-control-allow-origin') === '*' && h.get('access-control-allow-credentials')?.toLowerCase() === 'true') add('low', 'Ασυνεπής ρύθμιση CORS', 'Wildcard με credentials: οι browsers απορρίπτουν credentialed access. Δεν αποδεικνύεται διαρροή.', 'Χρησιμοποίησε συγκεκριμένο επιτρεπόμενο origin ή αφαίρεσε credentials.');
  for (const cookie of h.getSetCookie?.() || []) {
    const name = cookie.split('=', 1)[0].replace(/[^\w.-]/g, '').slice(0, 80);
    const attrs = cookie.split(';').slice(1).map(a => a.trim().toLowerCase());
    const evidence = 'Cookie: ' + (name || '[unnamed]') + ' (η τιμή αφαιρέθηκε)';
    if (secure && !attrs.includes('secure')) add('medium', 'Cookie χωρίς Secure', evidence, 'Πρόσθεσε Secure στα cookies που απαιτούν HTTPS.');
    if (!attrs.includes('httponly')) add('low', 'Cookie χωρίς HttpOnly', evidence, 'Για session cookies πρόσθεσε HttpOnly. Cookies που διαβάζονται νόμιμα από JavaScript χρειάζονται ξεχωριστή αξιολόγηση.');
    const sameSite = attrs.find(a => a.startsWith('samesite='));
    if (!sameSite || !/^samesite=(lax|strict|none)$/.test(sameSite)) add('low', 'SameSite λείπει ή είναι άκυρο', evidence, 'Όρισε έγκυρο SameSite ανάλογα με τη χρήση.');
    if (sameSite === 'samesite=none' && !attrs.includes('secure')) add('medium', 'SameSite=None χωρίς Secure', evidence, 'Συνδύασε SameSite=None με Secure.');
  }
  if (!isHtml) return [];
  const $ = cheerio.load(html); const links = new Set();
  let base = url;
  try { if ($('base[href]').first().attr('href')) base = new URL($('base[href]').first().attr('href'), url).href; } catch {}
  $('form').each((_, el) => {
    try { const action = new URL($(el).attr('action') || url, base); if (secure && action.protocol === 'http:') add('high', 'Form υποβάλλεται μέσω HTTP', safeUrl(action.href), 'Χρησιμοποίησε HTTPS για υποβολή φορμών.'); }
    catch { add('info', 'Μη έγκυρο form action', 'Δεν ήταν δυνατή η ανάλυση μιας διεύθυνσης φόρμας.', 'Διόρθωσε το URL της φόρμας.'); }
  });
  $('script[src],img[src],iframe[src],audio[src],video[src],source[src],link[rel="stylesheet"][href]').each((_, el) => {
    try {
      const asset = new URL($(el).attr('src') || $(el).attr('href'), base);
      if (secure && asset.protocol === 'http:') add('medium', 'Πόρος μέσω HTTP σε HTTPS σελίδα', safeUrl(asset.href), 'Φόρτωσε τον πόρο μέσω HTTPS.');
      if (['script', 'link'].includes(el.tagName) && ['http:', 'https:'].includes(asset.protocol) && asset.origin !== new URL(url).origin && !$(el).attr('integrity')) add('low', 'Εξωτερικός πόρος χωρίς SRI', safeUrl(asset.href), 'Εξέτασε SRI για σταθερές εκδόσεις εξωτερικών scripts/stylesheets.');
    } catch {}
  });
  $('a[href]').each((_, el) => {
    if (links.size >= 100) return;
    try { const u = parseUrl(new URL($(el).attr('href'), base).href); if (u.origin === new URL(url).origin) links.add(u.href); } catch {}
  });
  return [...links];
}

async function runScan(input, options = {}) {
  const { maxPages = 10, progress = () => {}, signal, transport = requestPage, sleep = delay, intervalMs = 500, deadlineMs = 180000 } = options;
  const root = parseUrl(input); const startedAt = new Date().toISOString();
  const deadline = AbortSignal.timeout(deadlineMs);
  const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
  const findings = [], pagesScanned = [], errors = [], skipped = [], redirects = [];
  const cap = Math.min(20, Math.max(1, Math.floor(Number(maxPages) || 10)));
  const queue = [root.href], attempted = new Set(); let scope = root.origin, tls = null, htmlPages = 0, cancelled = false;
  while (queue.length && attempted.size < cap + 5 && pagesScanned.length < cap) {
    if (combined.aborted) { cancelled = Boolean(signal?.aborted); errors.push({ url: safeUrl(root.href), error: cancelled ? 'Ακυρώθηκε από τον χρήστη.' : 'Συνολικό χρονικό όριο.' }); break; }
    const current = queue.shift(); if (attempted.has(current)) continue;
    try {
      if (attempted.size) await sleep(intervalMs, combined);
      attempted.add(current);
      progress({ stage: 'crawl', message: 'Έλεγχος ' + (pagesScanned.length + 1) + '/' + cap + ' · ' + new URL(current).hostname, percent: Math.min(75, 5 + Math.round(attempted.size / (cap + 5) * 70)) });
      const response = await transport(current, { signal: combined });
      if (response.tls && !tls) tls = response.tls;
      if ([301,302,303,307,308].includes(response.status)) {
        const location = response.headers.get('location'); if (!location) throw new Error('Redirect χωρίς Location.');
        const next = parseUrl(new URL(location, current).href); const from = new URL(current);
        redirects.push({ from: safeUrl(current), to: safeUrl(next.href), status: response.status });
        if (from.protocol === 'https:' && next.protocol === 'http:') findings.push(finding('high', 'Υποβάθμιση HTTPS σε HTTP', safeUrl(next.href), 'Διατήρησε HTTPS σε όλες τις ανακατευθύνσεις.', current));
        const upgrade = !pagesScanned.length && from.hostname === next.hostname && from.protocol === 'http:' && next.protocol === 'https:';
        if ((next.origin === scope || upgrade) && redirects.length <= 5) {
          if (attempted.has(next.href)) throw new Error('Βρόχος ανακατευθύνσεων.');
          if (upgrade) scope = next.origin; queue.unshift(next.href);
        } else skipped.push({ url: safeUrl(next.href), reason: 'Redirect εκτός εγκεκριμένου origin ή πάνω από το όριο. Για άλλο hostname ξεκίνα νέα εξουσιοδοτημένη σάρωση.' });
        continue;
      }
      if (response.status < 200 || response.status >= 300) throw new Error('HTTP ' + response.status + ': η σελίδα δεν αξιολογήθηκε.');
      const links = inspectPage(current, response, response.html, findings);
      pagesScanned.push(safeUrl(current));
      if (/text\/html|application\/xhtml\+xml/i.test(response.headers.get('content-type') || '')) htmlPages++;
      if (new URL(current).protocol === 'http:') findings.push(finding('high', 'Η σελίδα εξυπηρετείται μέσω HTTP', 'Η τελική απάντηση δεν χρησιμοποιεί κρυπτογράφηση.', 'Ανακατεύθυνε τη σελίδα σε HTTPS.', current));
      for (const link of links) if (!attempted.has(link) && !queue.includes(link) && queue.length < 100) queue.push(link);
    } catch (error) {
      errors.push({ url: safeUrl(current), error: combined.aborted ? 'Η εργασία διακόπηκε.' : safeText(error.message) });
      if (/CERT|TLS|SSL|SELF_SIGNED|UNABLE_TO_VERIFY/.test(error.code || '')) findings.push(finding('high', 'Αποτυχία ασφαλούς σύνδεσης TLS', String(error.code), 'Έλεγξε πιστοποιητικό, hostname και αλυσίδα εμπιστοσύνης.', current));
      if (combined.aborted) { cancelled = Boolean(signal?.aborted); break; }
    }
  }
  if (tls?.validTo && new Date(tls.validTo) - Date.now() < 30 * 86400000) findings.push(finding('medium', 'Πιστοποιητικό λήγει σύντομα', 'Λήξη: ' + tls.validTo, 'Ανανέωσε το πιστοποιητικό και ενεργοποίησε αυτόματη ανανέωση.', root.href));
  const unique = [...new Map(findings.map(f => [f.title + '|' + f.url + '|' + f.evidence, f])).values()].sort((a, b) => severityWeight[b.severity] - severityWeight[a.severity]);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }; unique.forEach(f => counts[f.severity]++);
  const limited = queue.some(url => !attempted.has(url));
  const status = cancelled ? 'cancelled' : !pagesScanned.length ? 'failed' : errors.length || skipped.length || limited ? 'partial' : 'complete';
  const groups = [...new Map(unique.map(f => [f.title, f])).values()];
  const score = status === 'complete' && htmlPages > 0 ? Math.max(0, 100 - groups.reduce((n, f) => n + severityWeight[f.severity], 0)) : null;
  return { schemaVersion: 2, target: safeUrl(root.href), startedAt, completedAt: new Date().toISOString(), status,
    methodology: 'Περιορισμένος έλεγχος HTTP/TLS configuration. Δεν εκτελεί JavaScript, exploits ή login. Το score αφορά μόνο τις συγκεκριμένες ρυθμίσεις και δεν πιστοποιεί ασφάλεια.',
    pagesScanned, tls, errors, skipped, redirects, coverage: { attempted: attempted.size, succeeded: pagesScanned.length, htmlPages, limit: cap, limited },
    summary: { score, counts, total: unique.length, issueGroups: groups.length }, findings: unique };
}
module.exports = { runScan, validatePublicUrl, inspectPage };

