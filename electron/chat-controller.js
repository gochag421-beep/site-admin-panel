const {chooseIntent,directIntent,explanationMessages}=require('../src/chat');const {chatCompletion}=require('../src/openrouter');const {searchCVEs}=require('../src/cve');const {safeText,sanitize}=require('../src/privacy');
function setupChat({handle,store,getKey,runProject,isBusy,getLive,cancel,emit}){
 const thinking=new Set();const searches=new Map();
 const post=(id,role,text,extra={})=>{const entry=store.addChat(id,role,text,extra);emit('chat:message',{projectId:id,message:entry});return entry;};
 handle('chat:get',id=>({messages:store.chat(id),research:store.research(id)}));
 handle('chat:send',async(id,text)=>{
  const project=store.project(id);if(typeof text!=='string'||!text.trim()||text.length>3000)throw new Error('Γράψε μήνυμα έως 3.000 χαρακτήρες.');
  const direct=directIntent(text);if(thinking.has(id)&&!['status','cancel'].includes(direct?.action))throw new Error('Περίμενε την τρέχουσα απάντηση. Η κατάσταση και η διακοπή παραμένουν διαθέσιμες.');
  const history=store.chat(id).slice();post(id,'user',safeText(text));
  if(direct?.action==='cancel'){cancel();searches.get(id)?.abort();return post(id,'assistant','Ζητήθηκε διακοπή. Τα διαθέσιμα αποτελέσματα διατηρούνται.');}
  if(direct?.action==='status')return post(id,'assistant',isBusy()?getLive():'Δεν εκτελείται σάρωση ιστοσελίδας αυτή τη στιγμή.');
  thinking.add(id);
  try{
   const key=getKey();const ask=key?messages=>chatCompletion(key,messages):null;const plan=await chooseIntent(text,ask);
   if(plan.action==='cancel'){cancel();searches.get(id)?.abort();return post(id,'assistant','Ζητήθηκε διακοπή.');}
   if(plan.action==='status')return post(id,'assistant',isBusy()?getLive():'Δεν εκτελείται σάρωση.');
   if(plan.action.startsWith('scan_')){
    if(!project.authorized)throw new Error('Επιβεβαίωσε πρώτα την άδεια στις ρυθμίσεις της ιστοσελίδας.');
    if(isBusy())return post(id,'assistant','Υπάρχει σάρωση σε εξέλιξη. Μπορείς να ζητήσεις εξήγηση της προηγούμενης αναφοράς ή να γράψεις «σταμάτα».');
    const mode=plan.action.slice(5);const names={full:'πλήρους σάρωσης',http:'HTTP / TLS',browser:'Chromium (με HTTP προέλεγχο)',cve:'γνωστών CVE / εξαρτήσεων'};
    post(id,'assistant',`Ξεκινά έλεγχος ${names[mode]} για ${project.url}. Θα εμφανίσω πραγματικά αποτελέσματα μόλις ολοκληρωθεί.`);
    runProject(id,{mode}).then(r=>post(id,'assistant',`Ο έλεγχος τελείωσε με κατάσταση: ${r.status}. Καταγράφηκαν ${r.summary.total} ευρήματα, ${(r.cveCandidates||[]).reduce((n,x)=>n+x.items.length,0)} υποψήφια αποτελέσματα NVD και ${r.errors.length} περιορισμοί/σφάλματα. Η αντιστοίχιση CVE δεν αποδεικνύει εκμεταλλευσιμότητα.`,{reportId:r.id})).catch(e=>post(id,'assistant','Ο έλεγχος δεν ολοκληρώθηκε: '+safeText(e.message)));
    return {started:true};
   }
   if(plan.action==='search_cve'){
    if(searches.has(id))return post(id,'assistant','Υπάρχει ήδη αναζήτηση NVD σε εξέλιξη.');
    const abort=new AbortController();searches.set(id,abort);post(id,'assistant',`Αναζητώ στο NVD: ${safeText(plan.query)}. Πρόκειται για αναζήτηση γνωστών αναφορών, όχι επιβεβαίωση ότι το site επηρεάζεται.`);
    searchCVEs(plan.query,{signal:abort.signal}).then(result=>{store.saveResearch(id,result);post(id,'assistant',`NVD: ${result.items.length} από ${result.total} αποτελέσματα. ${result.note}`,{research:result});}).catch(e=>post(id,'assistant',`Η αναζήτηση δεν ολοκληρώθηκε: ${safeText(e.message)}`)).finally(()=>searches.delete(id));return {started:true};
   }
   const last=store.history(id)[0];const report=last?store.report(last.id):null;
   if(!ask)return post(id,'assistant',`Για ελεύθερη συζήτηση και εξήγηση χρειάζεται OpenRouter API key στις Ρυθμίσεις. Οι εντολές «κάνε scan», «έλεγξε SSL», «κάνε scan για CVE», «ψάξε CVE για WordPress», «κατάσταση» και «σταμάτα» λειτουργούν και χωρίς AI. ${report?`Τελευταία αναφορά: ${report.status}, ${report.summary.total} ευρήματα.`:'Δεν υπάρχει ακόμη αναφορά.'}`);
   const answer=await ask(explanationMessages(text,history,project,report,store.research(id),isBusy()?getLive():'idle'));
   return post(id,'assistant',answer.text);
  }catch(e){return post(id,'assistant','Δεν ολοκληρώθηκε η απάντηση: '+safeText(e.message));}finally{thinking.delete(id);}
 });
}
module.exports={setupChat};
