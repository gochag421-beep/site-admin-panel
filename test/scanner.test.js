const test = require('node:test');
const assert = require('node:assert/strict');
const { runScan, inspectPage, validatePublicUrl } = require('../src/scanner');
const page = (html = '', extra = {}) => ({ status: 200, headers: new Headers({ 'content-type':'text/html', ...extra }), html });
const options = transport => ({ transport, sleep: async () => {} });
test('blocks credentials, local targets and unsupported protocols', async () => {
  await assert.rejects(() => validatePublicUrl('https://user:pass@example.com'), /credentials/);
  await assert.rejects(() => validatePublicUrl('file:///etc/passwd'), /Only HTTP/);
  await assert.rejects(() => validatePublicUrl('http://127.0.0.1'), /Local, private/);
});
test('failed scan has no score and no successful pages', async () => {
  const r = await runScan('https://example.com', options(async () => { throw Error('offline'); }));
  assert.equal(r.status, 'failed'); assert.equal(r.summary.score, null); assert.equal(r.pagesScanned.length, 0); assert.equal(r.errors.length, 1);
});
test('HTTP upgrades to HTTPS on same host and does not report insecure final page', async () => {
  const calls = [];
  const r = await runScan('http://example.com', options(async url => {
    calls.push(url); return url.startsWith('http:') ? { status: 301, headers: new Headers({ location:'https://example.com/' }) } : page();
  }));
  assert.deepEqual(calls, ['http://example.com/','https://example.com/']); assert.equal(r.status, 'complete');
  assert.ok(!r.findings.some(f => f.title.includes('μέσω HTTP')));
});
test('cross-host redirect stays out of scope', async () => {
  let calls = 0;
  const r = await runScan('https://example.com', options(async () => { calls++; return { status: 302, headers: new Headers({ location:'https://other.example/' }) }; }));
  assert.equal(calls, 1); assert.equal(r.skipped.length, 1); assert.equal(r.summary.score, null);
});
test('cookie values and query values never enter reports', async () => {
  const r = await runScan('https://example.com/?token=PRIVATE_QUERY', options(async () => page('<img src="http://cdn.example/i?x=PRIVATE_ASSET">', { 'set-cookie':'session=PRIVATE_COOKIE; SameSite=None' })));
  assert.doesNotMatch(JSON.stringify(r), /PRIVATE_/);
  assert.ok(r.findings.some(f => f.title === 'Cookie χωρίς Secure'));
});
test('ordinary HTTP hyperlinks and same-origin absolute scripts are not mixed-content/SRI findings', () => {
  const findings = [];
  inspectPage('https://example.com/', page(), '<a href="http://other.example/">Link</a><script src="https://example.com/app.js"></script><form action="http://[bad"></form>', findings);
  assert.ok(!findings.some(f => /Πόρος|Εξωτερικός/.test(f.title)));
  assert.ok(findings.some(f => f.title.includes('form action')));
});
test('protocol-relative external script gets SRI finding', () => {
  const findings = []; inspectPage('https://example.com/', page(), '<script src="//cdn.example/app.js"></script>', findings);
  assert.ok(findings.some(f => f.title.includes('SRI')));
});
test('HTTP errors produce partial coverage, not a reassuring score', async () => {
  const r = await runScan('https://example.com', options(async url => url.endsWith('/bad') ? { status: 500, headers: new Headers() } : page('<a href="/bad">bad</a>')));
  assert.equal(r.status, 'partial'); assert.equal(r.summary.score, null); assert.equal(r.pagesScanned.length, 1);
});
test('attempt cap includes failed requests and reports unvisited queue', async () => {
  let calls = 0;
  const r = await runScan('https://example.com', { ...options(async url => {
    calls++; if (!url.endsWith('/')) throw Error('offline');
    return page(Array.from({length:40}, (_,i) => '<a href="/p' + i + '">x</a>').join(''));
  }), maxPages: 2 });
  assert.equal(calls, 7); assert.equal(r.coverage.limited, true); assert.equal(r.status, 'partial');
});
test('score counts each issue category once across pages', async () => {
  const single = await runScan('https://example.com', options(async () => page()));
  const multi = await runScan('https://example.com', options(async url => page(url.endsWith('/') ? '<a href="/two">two</a>' : '')));
  assert.equal(single.summary.score, multi.summary.score); assert.equal(multi.pagesScanned.length, 2);
});
test('cancellation preserves collected findings', async () => {
  const c = new AbortController();
  const r = await runScan('https://example.com', { ...options(async () => { c.abort(); return page('<a href="/next">next</a>'); }), signal:c.signal });
  assert.equal(r.status, 'cancelled'); assert.equal(r.pagesScanned.length, 1); assert.equal(r.summary.score, null);
});
test('redirect loop ends with visible error', async () => {
  const r = await runScan('https://example.com', options(async () => ({ status: 302, headers: new Headers({ location:'/' }) })));
  assert.equal(r.status, 'failed'); assert.equal(r.errors.length, 1);
});

