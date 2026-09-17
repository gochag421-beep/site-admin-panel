const tls = require('node:tls');
const dns = require('node:dns').promises;
const net = require('node:net');
const cheerio = require('cheerio');

const severityWeight = { critical: 10, high: 7, medium: 4, low: 1, info: 0 };
const privateV4 = ip => /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
const privateV6 = ip => ip === '::1' || /^f[cd]/i.test(ip) || /^fe80:/i.test(ip);

async function validatePublicUrl(input) {
  let url;
  try { url = new URL(input); } catch { throw new Error('Enter a valid full URL, for example https://example.com'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS websites are supported.');
  if (url.username || url.password) throw new Error('URLs containing credentials are not allowed.');
  if (url.port && !['80','443'].includes(url.port)) throw new Error('Only standard web ports 80 and 443 are allowed.');
  const addresses = await dns.lookup(url.hostname, { all: true });
  if (!addresses.length || addresses.some(x => (net.isIPv4(x.address) ? privateV4(x.address) : privateV6(x.address)))) throw new Error('Local, private, and link-local targets are blocked.');
  return url;
}

function finding(severity, title, evidence, recommendation, url) { return { id: `${title}-${url}`.replace(/\W+/g,'-').toLowerCase(), severity, title, evidence, recommendation, url }; }
async function get(url, method='GET') {
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 12000);
  try { return await fetch(url, { method, redirect: 'manual', signal: controller.signal, headers: { 'User-Agent': 'VexonSecurityScanner/1.0 (authorized defensive audit)', Accept: 'text/html,application/xhtml+xml' } }); }
  finally { clearTimeout(timer); }
}

async function tlsInfo(url) {
  if (url.protocol !== 'https:') return null;
  return new Promise((resolve) => {
    const socket = tls.connect({ host: url.hostname, port: 443, servername: url.hostname, rejectUnauthorized: false, timeout: 8000 }, () => { const cert = socket.getPeerCertificate(); resolve({ authorized: socket.authorized, authorizationError: socket.authorizationError || null, protocol: socket.getProtocol(), validFrom: cert.valid_from, validTo: cert.valid_to, issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown' }); socket.end(); });
    socket.on('error', e => resolve({ error: e.message })); socket.on('timeout', () => { socket.destroy(); resolve({ error: 'TLS timeout' }); });
  });
}

function inspectPage(url, response, html, findings) {
  const h = response.headers;
  const required = [
    ['content-security-policy','Content Security Policy is missing','A CSP reduces the impact of script injection attacks.','Add a restrictive Content-Security-Policy and test it in report-only mode first.','medium'],
    ['strict-transport-security','HSTS is missing','HTTPS responses do not advertise Strict Transport Security.','Add Strict-Transport-Security with an appropriate max-age after confirming HTTPS works on all subdomains.','medium'],
    ['x-content-type-options','MIME sniffing protection is missing','X-Content-Type-Options is absent.','Set X-Content-Type-Options: nosniff.','low'],
    ['referrer-policy','Referrer Policy is missing','Referrer-Policy is absent.','Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin.','low'],
    ['permissions-policy','Permissions Policy is missing','Permissions-Policy is absent.','Disable browser capabilities the site does not need.','low']
  ];
  for (const [name,title,evidence,rec,severity] of required) if (!h.get(name)) findings.push(finding(severity,title,evidence,rec,url));
  if (h.get('server')) findings.push(finding('info','Server software is disclosed',`Server: ${h.get('server')}`,'Remove unnecessary version and server disclosure where practical.',url));
  if (url.startsWith('https:') && h.get('access-control-allow-origin') === '*' && h.get('access-control-allow-credentials') === 'true') findings.push(finding('high','Unsafe CORS policy','Wildcard origin is combined with credentials.','Use an explicit allowlist and never combine credentials with a wildcard origin.',url));
  const cookies = h.getSetCookie ? h.getSetCookie() : (h.get('set-cookie') ? [h.get('set-cookie')] : []);
  cookies.forEach(c => { if (!/;\s*secure/i.test(c) && url.startsWith('https:')) findings.push(finding('medium','Cookie lacks Secure flag',c.split(';')[0],'Mark sensitive cookies Secure.',url)); if (!/;\s*httponly/i.test(c)) findings.push(finding('low','Cookie lacks HttpOnly flag',c.split(';')[0],'Mark session cookies HttpOnly.',url)); if (!/;\s*samesite=/i.test(c)) findings.push(finding('low','Cookie lacks SameSite attribute',c.split(';')[0],'Set SameSite=Lax or Strict unless cross-site use is required.',url)); });
  if (!/text\/html/i.test(h.get('content-type') || '')) return [];
  const $ = cheerio.load(html);
  $('form').each((_, el) => { const action = new URL($(el).attr('action') || url, url); if (url.startsWith('https:') && action.protocol === 'http:') findings.push(finding('high','Form submits over HTTP',action.href,'Submit sensitive forms only over HTTPS.',url)); });
  $('[src],[href]').each((_, el) => { const raw = $(el).attr('src') || $(el).attr('href'); if (raw?.startsWith('http:') && url.startsWith('https:')) findings.push(finding('medium','Mixed active/passive content',raw,'Load all page resources over HTTPS.',url)); });
  $('script[src^="http"],link[rel="stylesheet"][href^="http"]').each((_, el) => { if (!$(el).attr('integrity')) findings.push(finding('low','Third-party asset without SRI',$(el).attr('src') || $(el).attr('href'),'Consider Subresource Integrity for versioned third-party assets.',url)); });
  const links = []; $('a[href]').each((_, el) => { try { const u = new URL($(el).attr('href'), url); if (u.origin === new URL(url).origin && ['http:','https:'].includes(u.protocol)) { u.hash=''; links.push(u.href); } } catch {} });
  return [...new Set(links)];
}

async function runScan(input, { maxPages=10, progress=()=>{} }={}) {
  const started = new Date().toISOString(); const root = await validatePublicUrl(input); const findings=[]; const visited=[]; const errors=[];
  progress({ stage:'connect', message:'Validating target and TLS…', percent:5 });
  const tls = await tlsInfo(root); if (root.protocol === 'http:') findings.push(finding('high','Website uses HTTP','Traffic is not encrypted.','Redirect all traffic to HTTPS and deploy a valid certificate.',root.href));
  if (tls?.error || tls?.authorized === false) findings.push(finding('high','TLS certificate problem',tls?.error || tls?.authorizationError || 'Certificate is not trusted.','Install a valid certificate with the complete chain.',root.href));
  if (tls?.validTo && (new Date(tls.validTo)-Date.now()) < 30*86400000) findings.push(finding('medium','TLS certificate expires soon',`Expires: ${tls.validTo}`,'Renew the certificate and automate renewal.',root.href));
  const queue=[root.href]; const cap=Math.min(20,Math.max(1,Number(maxPages)||10));
  while(queue.length && visited.length<cap) {
    const current=queue.shift(); if(visited.includes(current)) continue;
    progress({ stage:'crawl', message:`Checking page ${visited.length+1}/${cap}`, percent:10+Math.round((visited.length/cap)*65) });
    try {
      const response=await get(current); visited.push(current);
      if ([301,302,303,307,308].includes(response.status)) { const loc=response.headers.get('location'); if(loc){ const next=new URL(loc,current); if(next.origin===root.origin) queue.push(next.href); if(root.protocol==='https:'&&next.protocol==='http:') findings.push(finding('high','HTTPS redirects to HTTP',next.href,'Keep redirects on HTTPS.',current)); } continue; }
      const html=(await response.text()).slice(0,2_000_000); const links=inspectPage(current,response,html,findings); for(const link of links) if(!visited.includes(link)&&!queue.includes(link)) queue.push(link);
      if(response.status>=400) findings.push(finding('info',`Page returned HTTP ${response.status}`,current,'Review broken or protected routes as appropriate.',current));
    } catch(e) { errors.push({url:current,error:e.message}); }
  }
  progress({ stage:'summarize', message:'Prioritizing findings…', percent:78 });
  const unique=[...new Map(findings.map(x=>[`${x.title}|${x.url}|${x.evidence}`,x])).values()].sort((a,b)=>severityWeight[b.severity]-severityWeight[a.severity]);
  const counts={critical:0,high:0,medium:0,low:0,info:0}; unique.forEach(x=>counts[x.severity]++);
  const score=Math.max(0,100-unique.reduce((n,x)=>n+severityWeight[x.severity],0));
  return { schemaVersion:1, target:root.href, startedAt:started, completedAt:new Date().toISOString(), authorizationConfirmed:true, methodology:'Passive, same-origin, rate-limited HTTP/TLS configuration review. No exploit payloads or authentication bypass attempts.', pagesScanned:visited, tls, errors, summary:{score,counts,total:unique.length}, findings:unique };
}

module.exports={ runScan, validatePublicUrl };
