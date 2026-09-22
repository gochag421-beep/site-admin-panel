const cheerio=require('cheerio');
const {validatePublicUrl,getPage,inspectTLS}=require('./network');
const {finding,summarize}=require('./findings');
const {safeUrl,safeText}=require('./privacy');
const headerRules=[['content-security-policy','csp','Content Security Policy απουσιάζει','medium','Πρόσθεσε CSP αφού τη δοκιμάσεις σε report-only mode.'],['strict-transport-security','hsts','HSTS απουσιάζει','medium','Ενεργοποίησε Strict-Transport-Security αφού επιβεβαιώσεις το HTTPS.'],['x-content-type-options','nosniff','Προστασία MIME sniffing απουσιάζει','low','Όρισε X-Content-Type-Options: nosniff.'],['referrer-policy','referrer','Referrer Policy απουσιάζει','low','Όρισε Referrer-Policy: strict-origin-when-cross-origin.'],['permissions-policy','permissions','Permissions Policy απουσιάζει','low','Απενεργοποίησε browser capabilities που δεν χρειάζονται.']];
const pageChecks=['csp','hsts','nosniff','referrer','permissions','frame','cookie-secure','cookie-httponly','cookie-samesite','mixed','sri','form-http','cors','server'];
function inspectPage(url,response,report) {
  const h=response.headers;const html=/text\/html|application\/xhtml/i.test(h['content-type']||'');
  const scope=`http:${safeUrl(url)}`;const add=(id,opts)=>report.findings.push(finding(id,{url,scope,...opts}));
  if(!html) return [];
  for(const id of pageChecks)report.coverage.push(`${scope}|${id}`);
  for(const [name,id,title,severity,recommendation] of headerRules) {
    if(id==='hsts'&&!url.startsWith('https:'))continue;
    if(!h[name])add(id,{title,severity,evidence:`HTTP ${response.status}; ${name}: δεν βρέθηκε`,recommendation});
  }
  if(!h['x-frame-options']&&!/frame-ancestors/i.test(h['content-security-policy']||''))add('frame',{title:'Δεν δηλώνεται προστασία framing',severity:'medium',evidence:'Απουσιάζουν X-Frame-Options και CSP frame-ancestors.',recommendation:'Όρισε frame-ancestors στη CSP ανάλογα με την επιθυμητή ενσωμάτωση.'});
  if(h.server)add('server',{title:'Δημοσιοποίηση λογισμικού server',severity:'info',evidence:`Server: ${safeText(h.server)}`,recommendation:'Αφαίρεσε μη απαραίτητα στοιχεία έκδοσης.'});
  if(h['access-control-allow-origin']==='*'&&h['access-control-allow-credentials']==='true')add('cors',{title:'Ασυμβίβαστη ρύθμιση CORS',severity:'low',kind:'observed',evidence:'Allow-Origin: * με Allow-Credentials: true. Οι browsers απορρίπτουν αυτόν τον συνδυασμό για credentialed requests.',recommendation:'Χρησιμοποίησε ρητή λίστα επιτρεπόμενων origins. Αυτό δεν αποδεικνύει διαρροή δεδομένων.'});
  const cookies=h['set-cookie']||[];
  for(const cookie of (Array.isArray(cookies)?cookies:[cookies])) {
    const name=cookie.split('=',1)[0].slice(0,100);const evidence=`Cookie ${name}: [VALUE REDACTED]`;
    for(const [id,pattern,title,rec] of [['cookie-secure',/;\s*secure(?:;|$)/i,'Cookie χωρίς Secure','Πρόσθεσε Secure στα cookies που μεταδίδονται με HTTPS.'],['cookie-httponly',/;\s*httponly(?:;|$)/i,'Cookie χωρίς HttpOnly','Επιβεβαίωσε τον σκοπό του cookie και πρόσθεσε HttpOnly στα session cookies.'],['cookie-samesite',/;\s*samesite=/i,'Cookie χωρίς ρητό SameSite','Όρισε SameSite=Lax ή Strict όταν είναι συμβατό με τη λειτουργία.']]) {
      if(id==='cookie-secure'&&!url.startsWith('https:'))continue;
      if(!pattern.test(cookie))add(id,{title,subject:name,evidence,recommendation:rec,severity:id==='cookie-secure'?'medium':'low'});
    }
  }
  const $=cheerio.load(response.body);
  report.technologies||=[];
  const hints=[String(h.server||''),String(h['x-powered-by']||''),$('meta[name="generator"]').attr('content')||''];
  for(const hint of hints){for(const name of ['WordPress','Drupal','Joomla','nginx','Apache','PHP']){
    const match=hint.match(new RegExp(name+'(?:[ /]+([0-9]+(?:\\.[0-9]+){1,3}))?','i'));
    if(match&&!report.technologies.some(t=>t.name===name))report.technologies.push({name,version:match[1]||null,evidence:safeText(hint),confidence:'banner-unverified'});
  }}
  $('form').each((_,el)=>{try{const action=new URL($(el).attr('action')||url,url);if(action.protocol==='http:'&&url.startsWith('https:'))add('form-http',{title:'Φόρμα υποβάλλεται μέσω HTTP',severity:'high',kind:'observed',subject:safeUrl(action.href),evidence:safeUrl(action.href),recommendation:'Χρησιμοποίησε HTTPS για την υποβολή της φόρμας.'});}catch{}});
  $('script[src],img[src],iframe[src],link[rel="stylesheet"][href],video[src],audio[src]').each((_,el)=>{
    try{const asset=new URL($(el).attr('src')||$(el).attr('href'),url);if(asset.protocol==='http:'&&url.startsWith('https:'))add('mixed',{title:'Πόρος με μη κρυπτογραφημένο URL',severity:'medium',kind:'observed',subject:safeUrl(asset.href),evidence:safeUrl(asset.href),recommendation:'Αντικατάστησε τον πόρο με HTTPS. Ο browser μπορεί να τον μπλοκάρει ή να τον αναβαθμίζει.'});
      if(['script','link'].includes(el.tagName)&&asset.origin!==new URL(url).origin&&!$(el).attr('integrity'))add('sri',{title:'Εξωτερικός πόρος χωρίς SRI',severity:'low',subject:safeUrl(asset.href),evidence:safeUrl(asset.href),recommendation:'Εξέτασε Subresource Integrity για σταθερές εκδόσεις εξωτερικών scripts/styles.'});}catch{}
  });
  const links=[];$('a[href]').each((_,el)=>{try{const u=new URL($(el).attr('href'),url);u.hash='';if(u.origin===new URL(url).origin&&!u.search&&!/logout|delete|remove|unsubscribe|signout/i.test(u.pathname))links.push(u.href);}catch{}});
  return [...new Set(links)];
}
async function runScan(input,{maxPages=10,progress=()=>{},signal,request=getPage,tlsRequest=inspectTLS,validate=validatePublicUrl}={}) {
  const report={schemaVersion:2,target:safeUrl(input),startedAt:new Date().toISOString(),pagesScanned:[],attempted:[],coverage:[],findings:[],errors:[],modules:{http:'pending',browser:'disabled',source:'disabled'},methodology:'Περιορισμένος HTTP/TLS έλεγχος. Τα ευρήματα είναι παρατηρήσεις και συστάσεις, όχι πλήρες penetration test.'};
  let root;try{root=await validate(input);}catch(e){report.errors.push({module:'http',error:safeText(e.message)});report.modules.http='failed';return summarize(report);}
  const tlsScope=`tls:${root.origin}`;report.tls=await tlsRequest(root.href,{signal});
  if(report.tls&&!report.tls.error){report.coverage.push(`${tlsScope}|tls-trust`,`${tlsScope}|tls-expiry`);
    if(!report.tls.authorized)report.findings.push(finding('tls-trust',{module:'tls',scope:tlsScope,url:root.origin,severity:'high',kind:'observed',title:'Πρόβλημα πιστοποιητικού TLS',evidence:report.tls.authorizationError,recommendation:'Έλεγξε όνομα host, εγκυρότητα και αλυσίδα πιστοποιητικού.'}));
    if(report.tls.validTo&&(new Date(report.tls.validTo)-Date.now())<30*86400000)report.findings.push(finding('tls-expiry',{module:'tls',scope:tlsScope,url:root.origin,severity:'medium',kind:'observed',title:'Το πιστοποιητικό λήγει σύντομα ή έχει λήξει',evidence:report.tls.validTo,recommendation:'Ανανέωσε το πιστοποιητικό και ενεργοποίησε αυτόματη ανανέωση.'}));
  }else if(report.tls?.error)report.errors.push({module:'tls',error:report.tls.error});
  const queue=[root.href];const seen=new Set();const cap=Math.min(20,Math.max(1,Number(maxPages)||10));
  while(queue.length&&seen.size<cap&&!signal?.aborted){
    const url=queue.shift();if(seen.has(url))continue;seen.add(url);report.attempted.push(safeUrl(url));
    progress({stage:'http',percent:5+Math.round(seen.size/cap*40),message:`HTTP: ${seen.size}/${cap}`});
    try {
      if(seen.size>1)await new Promise(r=>setTimeout(r,300));
      const response=await request(url,{signal});
      if([301,302,303,307,308].includes(response.status)){
        const next=new URL(response.headers.location,url);next.hash='';
        if(next.origin===root.origin||(next.hostname===root.hostname&&new URL(url).protocol==='http:'&&next.protocol==='https:'))queue.push(next.href);
        else report.errors.push({module:'http',url:safeUrl(url),error:'Redirect εκτός επιτρεπόμενου origin δεν ακολουθήθηκε.'});
        continue;
      }
      if(response.status<200||response.status>=300){report.errors.push({module:'http',url:safeUrl(url),error:`HTTP ${response.status}`});continue;}
      report.pagesScanned.push(safeUrl(url));
      if(url.startsWith('http:'))report.findings.push(finding('http-plaintext',{url,severity:'high',kind:'observed',title:'Σελίδα εξυπηρετείται με HTTP',evidence:`HTTP ${response.status}`,recommendation:'Ενεργοποίησε HTTPS και ανακατεύθυνση HTTP σε HTTPS.'}));
      report.coverage.push(`http:${safeUrl(url)}|http-plaintext`);
      const links=inspectPage(url,response,report);for(const link of links)if(!seen.has(link)&&!queue.includes(link)&&queue.length<100)queue.push(link);
    }catch(e){report.errors.push({module:'http',url:safeUrl(url),error:safeText(e.message)});}
  }
  if(!report.pagesScanned.length&&!report.errors.length)report.errors.push({module:'http',error:'Δεν ελέγχθηκε επιτυχώς καμία σελίδα (redirect loop ή όριο).'});
  report.cancelled=Boolean(signal?.aborted);report.modules.http=report.errors.some(e=>['http','tls'].includes(e.module))?'partial':'complete';report.completedAt=new Date().toISOString();return summarize(report);
}
module.exports={runScan,validatePublicUrl,inspectPage};
