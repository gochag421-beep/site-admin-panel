const test=require('node:test'); const assert=require('node:assert/strict'); const {validatePublicUrl}=require('../src/scanner');
test('blocks credential URLs',async()=>{await assert.rejects(()=>validatePublicUrl('https://user:pass@example.com'),/credentials/)});
test('blocks unsupported protocols',async()=>{await assert.rejects(()=>validatePublicUrl('file:///etc/passwd'),/Only HTTP/)});
test('blocks localhost',async()=>{await assert.rejects(()=>validatePublicUrl('http://127.0.0.1'),/Local, private/)});
