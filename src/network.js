const dns = require('node:dns').promises;
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const ipaddr = require('ipaddr.js');
function publicIP(ip) {
  try { let address=ipaddr.parse(ip); if(address.kind()==='ipv6' && address.isIPv4MappedAddress()) address=address.toIPv4Address(); return address.range()==='unicast'; } catch {return false;}
}
async function resolvePublic(input) {
  let url; try {url=new URL(input);}catch{throw new Error('Enter a valid full URL, for example https://example.com');}
  if(!['http:','https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS websites are supported.');
  if(url.username || url.password) throw new Error('URLs containing credentials are not allowed.');
  if(url.port && !['80','443'].includes(url.port)) throw new Error('Only standard web ports 80 and 443 are allowed.');
  const host=url.hostname.replace(/^\[|\]$/g,'');
  const addresses=await dns.lookup(host,{all:true});
  if(!addresses.length || addresses.some(a=>!publicIP(a.address))) throw new Error('Local, private, reserved and link-local targets are blocked.');
  return {url,host,...addresses[0]};
}
async function validatePublicUrl(input){return (await resolvePublic(input)).url;}
function pinnedLookup(address,family){return (_hostname,opts,cb)=> typeof opts==='object' && opts.all ? cb(null,[{address,family}]) : cb(null,address,family);}
async function getPage(input,{signal,maxBytes=2_000_000,cookie=''}={}) {
  const {url,address,family}=await resolvePublic(input);
  return new Promise((resolve,reject)=>{
    const req=(url.protocol==='https:'?https:http).request(url,{method:'GET',lookup:pinnedLookup(address,family),agent:false,signal,headers:{'User-Agent':'VexonSecurityScanner/4.0 (authorized audit)',Accept:'text/html,application/xhtml+xml',...(cookie?{Cookie:cookie}:{})}},res=>{
      let length=0; const chunks=[];
      res.on('data',chunk=>{length+=chunk.length;if(length>maxBytes)req.destroy(new Error('Page exceeds 2 MB limit'));else chunks.push(chunk);});
      res.on('error',reject);
      res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString('utf8')}));
    });
    const timer=setTimeout(()=>req.destroy(new Error('HTTP timeout')),15000);
    req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end();
  });
}
async function inspectTLS(input,{signal}={}) {
  const target=await resolvePublic(input);if(target.url.protocol!=='https:')return null;
  return new Promise(resolve=>{
    let done=false;const finish=result=>{if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);socket.destroy();resolve(result);};
    const socket=tls.connect({host:target.address,port:Number(target.url.port)||443,servername:net.isIP(target.host)?undefined:target.host,rejectUnauthorized:false},()=>{
      const cert=socket.getPeerCertificate();const hostError=tls.checkServerIdentity(target.host,cert);
      finish({authorized:socket.authorized&&!hostError,authorizationError:hostError?.message||socket.authorizationError||null,protocol:socket.getProtocol(),validTo:cert.valid_to,issuer:cert.issuer?.O||cert.issuer?.CN});
    });
    const timer=setTimeout(()=>finish({error:'TLS timeout'}),10000);
    const abort=()=>finish({error:'Scan cancelled'});signal?.addEventListener('abort',abort,{once:true});
    socket.on('error',()=>finish({error:'TLS connection failed'}));if(signal?.aborted)abort();
  });
}
// A loopback-only Chromium proxy pins every outbound connection to a validated public IP.
async function startBrowserProxy() {
  const sockets=new Set();
  const track=s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));s.on('error',()=>{});s.setTimeout(20000,()=>s.destroy());return s;};
  const server=http.createServer(async(req,res)=>{
    try {if(!['GET','HEAD'].includes(req.method))throw new Error('Read-only');
      const t=await resolvePublic(req.url);if(t.url.protocol!=='http:')throw new Error('Protocol');
      const headers={...req.headers};delete headers['proxy-authorization'];delete headers['proxy-connection'];
      const outgoing=http.request(t.url,{method:req.method,headers,agent:false,lookup:pinnedLookup(t.address,t.family)},up=>{res.writeHead(up.statusCode,up.headers);up.pipe(res);});
      outgoing.on('socket',track);outgoing.on('error',()=>{if(!res.headersSent)res.writeHead(502);res.end();});req.pipe(outgoing);
    }catch{res.writeHead(403);res.end();}
  });
  server.on('connection',track);
  server.on('connect',async(req,client,head)=>{
    try {const t=await resolvePublic('https://'+req.url);if(Number(t.url.port||443)!==443)throw new Error('Port');
      const upstream=track(net.connect(443,t.address,()=>{client.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)upstream.write(head);upstream.pipe(client);client.pipe(upstream);}));
      client.on('close',()=>upstream.destroy());upstream.on('error',()=>client.destroy());
    }catch{client.end('HTTP/1.1 403 Forbidden\r\n\r\n');}
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  return {port:server.address().port,close:()=>{for(const s of sockets)s.destroy();server.close();}};
}
module.exports={publicIP,resolvePublic,validatePublicUrl,pinnedLookup,getPage,inspectTLS,startBrowserProxy};
