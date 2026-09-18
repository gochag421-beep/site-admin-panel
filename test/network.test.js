const test = require('node:test'), assert = require('node:assert/strict');
const http = require('node:http'), { EventEmitter } = require('node:events');
const { isPublicAddress, resolvePublic, requestPage } = require('../src/network');
test('rejects special IPv4, IPv6 and mapped private addresses', () => {
  for (const ip of ['0.0.0.0','10.1.2.3','127.0.0.1','169.254.169.254','100.64.0.1','192.168.0.1','224.0.0.1','255.255.255.255','::','::1','::ffff:127.0.0.1','fc00::1','fe80::1','ff02::1','2001:db8::1']) assert.equal(isPublicAddress(ip), false, ip);
  for (const ip of ['1.1.1.1','8.8.8.8','2606:4700:4700::1111']) assert.equal(isPublicAddress(ip), true, ip);
});
test('rejects a DNS answer containing any private address', async () => {
  await assert.rejects(() => resolvePublic('https://example.com', { lookup:async () => [{address:'1.1.1.1',family:4},{address:'127.0.0.1',family:4}] }), /non-public/);
});
test('DNS is bounded and cancellation interrupts lookup', async () => {
  await assert.rejects(() => resolvePublic('https://example.com', { lookup:() => new Promise(() => {}), timeoutMs:10 }), /DNS timeout/);
  const c = new AbortController(); c.abort();
  await assert.rejects(() => resolvePublic('https://example.com', { lookup:async () => [], signal:c.signal }), /ακυρώθηκε/);
});
function fakeRequest(t, emitResponse) {
  t.mock.method(http, 'request', (url, options) => {
    const req = new EventEmitter(); req.destroy = err => { if (err) queueMicrotask(() => req.emit('error', err)); };
    req.end = () => queueMicrotask(() => emitResponse(req, options));
    return req;
  });
}
function response() { const res = new EventEmitter(); res.headers = {'content-type':'text/html'}; res.statusCode = 200; res.destroy = () => {}; return res; }
const lookup = async () => [{address:'1.1.1.1',family:4}];
test('transport pins the verified address without resolving again', async t => {
  let lookups = 0;
  fakeRequest(t, (req, options) => {
    options.lookup('example.com', {all:true}, (err, addresses) => { assert.equal(err,null); assert.deepEqual(addresses,[{address:'1.1.1.1',family:4}]); });
    const res = response(); req.emit('response',res); res.emit('data',Buffer.from('ok')); res.emit('end');
  });
  const r = await requestPage('http://example.com', { lookup:async () => { lookups++; return lookup(); } });
  assert.equal(r.html,'ok'); assert.equal(lookups,1);
});
test('body byte limit aborts download before full buffering', async t => {
  fakeRequest(t, req => { const res = response(); req.emit('response',res); res.emit('data',Buffer.alloc(11)); });
  await assert.rejects(() => requestPage('http://example.com', {lookup,maxBytes:10}), error => error.code === 'BODY_LIMIT');
});
test('timeout remains active after headers arrive', async t => {
  fakeRequest(t, req => { req.emit('response',response()); });
  await assert.rejects(() => requestPage('http://example.com', {lookup,timeoutMs:15}), error => error.code === 'TIMEOUT');
});
test('body cancellation stops pending request', async t => {
  const c = new AbortController();
  fakeRequest(t, req => { req.emit('response',response()); c.abort(); });
  await assert.rejects(() => requestPage('http://example.com', {lookup,signal:c.signal}), error => error.name === 'AbortError');
});

