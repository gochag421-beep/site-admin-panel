const test=require('node:test');
const assert=require('node:assert/strict');
const {isFree,analyzeWithOpenRouter}=require('../src/openrouter');
const model=(id,pricing={prompt:'0',completion:'0'})=>({id,pricing});
const report={target:'https://example.com',summary:{},findings:[]};
const result=(status,json)=>({ok:status===200,status,headers:new Headers(),json:async()=>json});
test('rejects paid and ambiguous prices even when name ends in free',()=>{
  assert.equal(isFree(model('a:free',{prompt:'1',completion:'0'})),false);
  assert.equal(isFree(model('a',{prompt:null,completion:'0'})),false);
  assert.equal(isFree(model('a',{prompt:'0',completion:'0',request:'0.01'})),false);
  assert.equal(isFree(model('a')),true);
});
test('429 then empty result then success rotates only through zero-priced models',async()=>{
  const calls=[];
  const fetchImpl=async(url,opts)=>{
    if(url.endsWith('/models')) return result(200,{data:[model('a'),model('b'),model('c'),model('paid:free',{prompt:'1',completion:'0'})]});
    const body=JSON.parse(opts.body); calls.push(body);
    if(body.model==='a') return result(429,{error:{code:429,message:'Provider temporarily rate limited'}});
    if(body.model==='b') return result(200,{choices:[{message:{content:''}}]});
    return result(200,{model:'c',choices:[{message:{content:'analysis'},finish_reason:'stop'}]});
  };
  const r=await analyzeWithOpenRouter('fake',null,report,{fetchImpl,sleep:async()=>{}});
  assert.equal(r.model,'c');
  assert.deepEqual(calls.map(c=>c.model),['a','b','c']);
  assert.ok(calls.every(c=>c.provider.max_price.prompt===0 && c.provider.max_price.completion===0 && c.provider.max_price.request===0));
});
test('account authentication error stops instead of cycling',async()=>{
  let calls=0;
  await assert.rejects(()=>analyzeWithOpenRouter('fake',null,report,{fetchImpl:async(url)=>{
    if(url.endsWith('/models')) return result(200,{data:[model('a'),model('b')]});
    calls++;return result(401,{error:{code:401}});
  },sleep:async()=>{}}),/κλειδί/);
  assert.equal(calls,1);
});
test('all unavailable models finish with a clear error',async()=>{
  await assert.rejects(()=>analyzeWithOpenRouter('fake',null,report,{fetchImpl:async(url)=>url.endsWith('/models')?result(200,{data:[model('a')]}):result(503,{error:{code:503}}),sleep:async()=>{}}),/1 δωρεάν/);
});
