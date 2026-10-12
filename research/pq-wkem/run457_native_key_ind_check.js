'use strict';
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
let checks = 0;
function ok(v, label) { assert.ok(v, label); checks++; }
function seed(i) { return crypto.createHash('sha256').update('run457-native-key:' + i).digest(); }
function makeKey(i) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed(i)]);
  const sk = crypto.createPrivateKey({key: der, format:'der', type:'pkcs8'});
  return {sk, vk: crypto.createPublicKey(sk)};
}
function pub(k) { return k.vk.export({format:'der', type:'spki'}); }
const n = 12;
const keys = Array.from({length:n}, (_, i) => makeKey(i));
const context = i => Buffer.from('run457|relation=disprove|UTXO=' + i + '|branch=challenge|window=1008');
let realAccepted = 0, independentAccepted = 0, wrongContextAccepted = 0;
for (let i=0; i<n; i++) {
  const message = context(i);
  const signature = crypto.sign(null, message, keys[i].sk);
  const honest = crypto.verify(null, message, keys[i].vk, signature);
  ok(honest, 'matching native signing key must verify');
  realAccepted += Number(honest);
  const wrongMessage = crypto.verify(null, context((i+1)%n), keys[i].vk, signature);
  ok(!wrongMessage, 'context change must reject');
  wrongContextAccepted += Number(wrongMessage);
  for (let j=0; j<n; j++) {
    if (j===i) continue;
    const alternateSignature = crypto.sign(null, message, keys[j].sk);
    const accepted = crypto.verify(null, message, keys[i].vk, alternateSignature);
    ok(!accepted, 'independent signing key must not pass this diagnostic fixture');
    independentAccepted += Number(accepted);
    ok(!pub(keys[i]).equals(pub(keys[j])), 'native public keys distinct in diagnostic');
  }
}
// Demonstrate that multiple valid source witnesses can point to precisely the same
// signing credential; this tests syntax, not secure source authentication.
const gate = (i, witness) => ['work-proof-A','tag-conflict-B'].includes(witness) ? seed(i) : null;
for(let i=0;i<n;i++) {
  ok(gate(i,'work-proof-A').equals(gate(i,'tag-conflict-B')), 'same capability for both valid witnesses');
  ok(gate(i,'invalid')===null, 'source verifier rejects invalid witness');
}
const pkDigest = crypto.createHash('sha256').update(Buffer.concat(keys.map(pub))).digest('hex');
const result={run:457,model:'public native signing-verification-key candidate test',algorithm:'Ed25519 NON-PQ diagnostic',fixture_count:n,real_accepted:realAccepted,independent_accepted:independentAccepted,independent_trials:n*(n-1),wrong_context_accepted:wrongContextAccepted,assertions:checks,public_keys_sha256:pkDigest,claim:'finite diagnostic only, not a cryptographic or QPT security proof'};
process.stdout.write(JSON.stringify(result,null,2)+'\n');
