let report = null, settings = { maxPages: 10, hasApiKey: false }, busy = false;
const $ = s => document.querySelector(s), $$ = s => document.querySelectorAll(s);
const labels = { scanner: 'Έλεγχος ασφαλείας', reports: 'Αναφορά ασφαλείας', settings: 'Ρυθμίσεις' };
const states = { complete: 'Ολοκληρωμένη', partial: 'Μερική', failed: 'Αποτυχημένη', cancelled: 'Ακυρωμένη' };
function show(id) {
  $$('.view,.nav').forEach(x => x.classList.remove('active'));
  $$('.nav').forEach(x => x.removeAttribute('aria-current'));
  $('#' + id).classList.add('active'); const nav = $('.nav[data-view="' + id + '"]');
  nav.classList.add('active'); nav.setAttribute('aria-current', 'page'); $('#pageTitle').textContent = labels[id];
}
function message(text = '') { $('#message').textContent = text; $('#message').classList.toggle('hidden', !text); }
function setBusy(value) {
  busy = value; $('#appStatus').textContent = value ? 'Εργασία σε εξέλιξη' : 'Έτοιμο';
  $('#scanBtn').disabled = value; $('#previewAiBtn').disabled = value || !report?.pagesScanned.length;
  $('#saveSettings').disabled = value; $('#deleteKey').disabled = value; $('#cancelBtn').disabled = false;
  $('#progressCard').classList.toggle('hidden', !value);
  if (value) { $('#progressBar').value = 0; $('#progressText').textContent = 'Προετοιμασία…'; message(); }
}
$$('.nav').forEach(button => button.onclick = () => show(button.dataset.view));
window.vexon.onProgress(p => { $('#progressText').textContent = p.message; $('#progressBar').value = Math.max(0, Math.min(100, Number(p.percent) || 0)); });
function updateSettings(value) {
  settings = value; $('#maxPages').value = settings.maxPages;
  $('#keyState').textContent = settings.hasApiKey ? 'Υπάρχει αποθηκευμένο κλειδί. Άφησέ το κενό για να διατηρηθεί.' : 'Δεν υπάρχει αποθηκευμένο κλειδί.';
}
window.vexon.getSettings().then(updateSettings).catch(e => message(e.message));
$('#settingsForm').onsubmit = async event => {
  event.preventDefault();
  try { updateSettings(await window.vexon.saveSettings({ apiKey: $('#apiKey').value.trim() || undefined, maxPages: Number($('#maxPages').value) })); $('#apiKey').value = ''; $('#saveMessage').textContent = 'Οι ρυθμίσεις αποθηκεύτηκαν.'; }
  catch (e) { $('#saveMessage').textContent = e.message; }
};
$('#deleteKey').onclick = async () => {
  try { updateSettings(await window.vexon.saveSettings({ clearApiKey: true, maxPages: Number($('#maxPages').value) })); $('#apiKey').value = ''; $('#saveMessage').textContent = 'Το κλειδί διαγράφηκε.'; }
  catch (e) { $('#saveMessage').textContent = e.message; }
};
$('#scanForm').onsubmit = async event => {
  event.preventDefault(); if (busy) return; setBusy(true);
  try {
    report = await window.vexon.scan({ url: $('#target').value.trim(), authorized: $('#authorized').checked, maxPages: settings.maxPages });
    $('#severityFilter').value = 'all'; render(report); show('reports');
  } catch (e) { message('Η σάρωση δεν ολοκληρώθηκε: ' + e.message); }
  finally { setBusy(false); }
};
$('#cancelBtn').onclick = async () => {
  try { await window.vexon.cancel(); $('#cancelBtn').disabled = true; $('#progressText').textContent = 'Ακύρωση…'; }
  catch (e) { message(e.message); }
};
function element(tag, text, className) { const node = document.createElement(tag); node.textContent = text; if (className) node.className = className; return node; }
function renderFindings() {
  const host = $('#findings'); host.replaceChildren(); const filter = $('#severityFilter').value;
  const selected = report.findings.filter(f => filter === 'all' || f.severity === filter || filter === 'high' && f.severity === 'critical');
  for (const f of selected) {
    const article = element('article', '', 'finding'), title = element('h3', '');
    const severity = ['critical','high','medium','low','info'].includes(f.severity) ? f.severity : 'info';
    title.append(element('span', severity, 'badge ' + severity), document.createTextNode(f.title));
    article.append(title, element('p', f.url, 'finding-url'), element('p', f.evidence), element('p', 'Διόρθωση: ' + f.recommendation));
    host.append(article);
  }
  if (!selected.length) host.append(element('p', report.status === 'failed' ? 'Δεν υπάρχουν επαρκή δεδομένα για αξιολόγηση.' : 'Δεν υπάρχουν ευρήματα για αυτό το φίλτρο.'));
}
$('#severityFilter').onchange = () => { if (report) renderFindings(); };
function render(r) {
  $('#empty').classList.add('hidden'); $('#report').classList.remove('hidden');
  $('#scoreValue').textContent = r.summary.score ?? '—';
  $('#scoreRing').className = r.summary.score === null ? 'unknown-score' : r.summary.score < 60 ? 'poor-score' : r.summary.score < 85 ? 'warn-score' : '';
  $('#reportState').textContent = states[r.status] || r.status;
  $('#targetName').textContent = new URL(r.target).hostname;
  $('#scanMeta').textContent = r.pagesScanned.length + ' επιτυχείς σελίδες · ' + new Date(r.completedAt).toLocaleString('el-GR');
  $('#coverageNote').textContent = r.methodology + (r.summary.score === null ? ' Δεν δίνεται βαθμολογία λόγω ελλιπούς κάλυψης ή απουσίας HTML.' : '');
  $('#coverageDetails').textContent = JSON.stringify({ target: r.target, coverage: r.coverage, pages: r.pagesScanned, tls: r.tls, redirects: r.redirects }, null, 2);
  $('#severity').replaceChildren();
  for (const s of ['critical','high','medium','low','info']) { const box = element('div', '', 'sev'); box.append(element('b', r.summary.counts[s]), element('small', s)); $('#severity').append(box); }
  $('#findingTotal').textContent = r.summary.total + ' ευρήματα · ' + r.summary.issueGroups + ' κατηγορίες';
  const issues = [...r.errors.map(e => e.url + ' — ' + e.error), ...r.skipped.map(e => e.url + ' — ' + e.reason)];
  if (r.coverage.limited) issues.push('Επιτεύχθηκε το όριο σελίδων/προσπαθειών. Υπάρχουν URLs που δεν ελέγχθηκαν.');
  $('#scanIssues').classList.toggle('hidden', !issues.length); $('#errorList').replaceChildren(...issues.map(t => element('p', t)));
  renderFindings();
  $('#aiText').textContent = r.ai?.text || r.ai?.error || 'Η αναφορά παραμένει τοπικά μέχρι να επιβεβαιώσεις αποστολή.';
  $('#modelBadge').textContent = r.ai?.model || 'OpenRouter';
  $('#aiAttempts').textContent = r.ai?.attempts?.length ? JSON.stringify(r.ai.attempts, null, 2) : 'Δεν έγιναν κλήσεις.';
  $('#previewAiBtn').disabled = busy || !r.pagesScanned.length;
}
$('#previewAiBtn').onclick = async () => {
  try {
    if (!settings.hasApiKey) { show('settings'); message('Πρόσθεσε πρώτα OpenRouter API key.'); return; }
    $('#aiPreview').textContent = JSON.stringify(await window.vexon.previewAI(report.id), null, 2);
    $('#aiConsent').checked = false; $('#analyzeBtn').disabled = true; $('#aiDialog').showModal();
  } catch (e) { message(e.message); }
};
$('#aiConsent').onchange = () => { $('#analyzeBtn').disabled = !$('#aiConsent').checked; };
$('#closeAiDialog').onclick = () => $('#aiDialog').close();
$('#analyzeBtn').onclick = async () => {
  if (!$('#aiConsent').checked || busy) return;
  $('#aiDialog').close(); setBusy(true);
  try { report = await window.vexon.analyze({ id: report.id, consent: true }); render(report); }
  catch (e) { message(e.message); }
  finally { setBusy(false); }
};
$('#exportBtn').onclick = async () => {
  try { if (report) { const file = await window.vexon.exportReport(report.id); if (file) message('Η αναφορά αποθηκεύτηκε.'); } }
  catch (e) { message('Αποτυχία εξαγωγής: ' + e.message); }
};

