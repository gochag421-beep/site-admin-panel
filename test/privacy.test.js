const test = require('node:test'), assert = require('node:assert/strict');
const { safeUrl, aiPayload } = require('../src/privacy');
test('all query values and URL credentials are removed', () => {
  const value = safeUrl('https://user:pass@example.com/path?q=private&token=secret#private');
  assert.doesNotMatch(value,/user|pass|private|secret/); assert.match(value,/redacted/);
});
test('AI payload is an allowlist with bounded evidence', () => {
  const value = aiPayload({target:'https://example.com/?x=hidden',rawBody:'HIDDEN',summary:{},status:'partial',findings:[{severity:'low',title:'Header',evidence:'a'.repeat(2000),recommendation:'Fix',url:'https://example.com',cookie:'HIDDEN'}]});
  assert.equal(value.findings[0].evidence.length,1000); assert.doesNotMatch(JSON.stringify(value),/HIDDEN|hidden/);
});

