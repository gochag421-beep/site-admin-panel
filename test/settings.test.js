const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createSettingsStore } = require('../src/settings');
const crypt = { isEncryptionAvailable:()=>true, encryptString:s=>Buffer.from('encrypted:'+s), decryptString:b=>b.toString().replace('encrypted:','') };
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'vexon-test-'));
  t.after(() => fs.rmSync(dir,{recursive:true,force:true}));
  const file = path.join(dir,'settings.json'); return {file, store:createSettingsStore(file,crypt)};
}
test('blank key preserves ciphertext, explicit removal deletes it', t => {
  const {file,store} = fixture(t); store.save({maxPages:10,apiKey:'fake-key'});
  const before = JSON.parse(fs.readFileSync(file)).apiKeyEncrypted;
  assert.equal(store.save({maxPages:5,apiKey:''}).hasApiKey,true);
  assert.equal(JSON.parse(fs.readFileSync(file)).apiKeyEncrypted,before);
  assert.equal(store.key(),'fake-key'); assert.equal(store.publicSettings().apiKey,undefined);
  assert.equal(store.save({maxPages:5,clearApiKey:true}).hasApiKey,false); assert.equal(store.key(),'');
});
test('rejects invalid settings without overwriting saved key', t => {
  const {store} = fixture(t); store.save({maxPages:10,apiKey:'fake-key'});
  for (const maxPages of [0,21,1.5,NaN,'10']) assert.throws(() => store.save({maxPages}));
  assert.equal(store.key(),'fake-key');
});
test('corrupt settings are surfaced instead of silently erased', t => {
  const {file,store} = fixture(t); fs.writeFileSync(file,'broken');
  assert.throws(() => store.save({maxPages:10}), /ρυθμίσεις/); assert.equal(fs.readFileSync(file,'utf8'),'broken');
});

