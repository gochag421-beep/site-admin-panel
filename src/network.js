const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns').promises;
const net = require('node:net');
const ipaddr = require('ipaddr.js');
function abortError() { return Object.assign(new Error('Η εργασία ακυρώθηκε.'), { name: 'AbortError' }); }
function isPublicAddress(address) {
  try { let ip = ipaddr.parse(address); if (ip.kind() === 'ipv6' && ip.isIPv4MappedAddress()) ip = ip.toIPv4Address(); return ip.range() === 'unicast'; } catch { return false; }
}
function parseUrl(input) {
  let url;
  try { url = new URL(input); } catch { throw new Error('Δώσε πλήρες URL, π.χ. https://example.gr'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS websites are supported.');
  if (url.username || url.password) throw new Error('URLs containing credentials are not allowed.');
  if (url.port) throw new Error('Επιτρέπεται μόνο η προεπιλεγμένη θύρα του HTTP/HTTPS.');
  url.hash = ''; return url;
}
function bounded(promise, signal, timeoutMs) {
  return new Promise((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', stop); };
    const stop = () => { cleanup(); reject(abortError()); };
    const timer = setTimeout(() => { cleanup(); reject(new Error('DNS timeout')); }, timeoutMs);
    if (signal?.aborted) return stop();
    signal?.addEventListener('abort', stop, { once: true });
    promise.then(value => { cleanup(); resolve(value); }, error => { cleanup(); reject(error); });
  });
}
async function resolvePublic(input, { lookup = dns.lookup, signal, timeoutMs = 5000 } = {}) {
  const url = parseUrl(input); const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const addresses = net.isIP(hostname) ? [{ address: hostname, family: net.isIP(hostname) }]
    : await bounded(lookup(hostname, { all: true, verbatim: true }), signal, timeoutMs);
  if (!addresses.length || addresses.some(x => !isPublicAddress(x.address))) throw new Error('Local, private, and non-public targets are blocked.');
  return { url, address: addresses[0] };
}
async function validatePublicUrl(input, options) { return (await resolvePublic(input, options)).url; }
async function requestPage(input, { signal, timeoutMs = 12000, maxBytes = 2_000_000, lookup } = {}) {
  const { url, address } = await resolvePublic(input, { lookup, signal });
  if (signal?.aborted) throw abortError();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (err, value) => {
      if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', cancel);
      if (err) reject(err); else resolve(value);
    };
    const pinnedLookup = (_host, opts, cb) => {
      if (typeof opts === 'function') { cb = opts; opts = {}; }
      if (opts?.all) cb(null, [address]); else cb(null, address.address, address.family);
    };
    const req = (url.protocol === 'https:' ? https : http).request(url, { method: 'GET', agent: false, lookup: pinnedLookup, rejectUnauthorized: true,
      headers: { 'User-Agent': 'VexonSecurityScanner/1.1 (authorized configuration review)', Accept: 'text/html,application/xhtml+xml', 'Accept-Encoding': 'identity' } });
    const cancel = () => req.destroy(abortError());
    const timer = setTimeout(() => req.destroy(Object.assign(new Error('Η λήψη ξεπέρασε το χρονικό όριο.'), { code: 'TIMEOUT' })), timeoutMs);
    signal?.addEventListener('abort', cancel, { once: true });
    req.on('response', res => {
      const socket = res.socket; const cert = url.protocol === 'https:' ? socket.getPeerCertificate() : null;
      const tls = cert ? { authorized: socket.authorized, protocol: socket.getProtocol(), validTo: cert.valid_to, issuer: cert.issuer?.O || cert.issuer?.CN || '' } : null;
      const headers = new Headers();
      for (const [key, values] of Object.entries(res.headers)) for (const value of Array.isArray(values) ? values : [values]) if (value !== undefined) headers.append(key, value);
      const result = { status: res.statusCode, headers, tls, html: '' };
      const htmlType = /text\/html|application\/xhtml\+xml/i.test(headers.get('content-type') || '');
      if (!htmlType || [301,302,303,307,308].includes(res.statusCode)) { finish(null, result); res.destroy(); return; }
      if (headers.get('content-encoding') && headers.get('content-encoding') !== 'identity') { finish(new Error('Μη υποστηριζόμενη συμπίεση απάντησης.')); res.destroy(); return; }
      let bytes = 0; const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxBytes) { finish(Object.assign(new Error('Η σελίδα υπερβαίνει το όριο μεγέθους.'), { code: 'BODY_LIMIT' })); res.destroy(); req.destroy(); }
        else chunks.push(chunk);
      });
      res.on('end', () => finish(null, { ...result, html: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', err => finish(err));
      res.on('aborted', () => finish(new Error('Η λήψη διακόπηκε πριν ολοκληρωθεί.')));
    });
    req.on('error', err => finish(err)); req.end();
  });
}
function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    const stop = () => { clearTimeout(timer); reject(abortError()); };
    const timer = setTimeout(() => { signal?.removeEventListener('abort', stop); resolve(); }, ms);
    signal?.addEventListener('abort', stop, { once: true });
  });
}
module.exports = { isPublicAddress, parseUrl, resolvePublic, validatePublicUrl, requestPage, delay, abortError };
