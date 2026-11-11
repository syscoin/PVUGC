// R216: synthetic BTC activation binding only. No witness KEM, native signer or PoW.
const C = require('crypto');
const H = b => C.createHash('sha256').update(b).digest();
const D = b => H(H(b));
const eq = (a,b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
const z = Buffer.alloc(32);
const base = Buffer.from('fixed-activation-base-with-vault-slot-7');
const txid = D(base);
const sign = a => C.createHmac('sha256','synthetic-notary-key').update(a).digest();
const witness = (a,s) => Buffer.concat([base,Buffer.from([a.length]),a,s]);
const wtxid = (a,s) => D(witness(a,s));
const root = (a,s) => D(Buffer.concat([z,wtxid(a,s)]));
const commit = (a,s) => D(Buffer.concat([root(a,s),z]));
const good = Buffer.from(JSON.stringify({slot:7,burn:2}));
const fake = Buffer.from(JSON.stringify({slot:7,burn:3}));
const sg = sign(good), sf = sign(fake);
const accepted = new Set([commit(good,sg).toString('hex')]);
const empty = new Set([2,3]); // synthetic fixed authenticated burn-state snapshot
const cases = {};
const naive = (a,s) => eq(s,sign(a)) && empty.has(JSON.parse(a).burn);
const strict = (a,s,merkleCommit) => naive(a,s) && JSON.parse(a).slot === 7 &&
  eq(commit(a,s),merkleCommit) && accepted.has(merkleCommit.toString('hex'));
function ck(name,value){ if(!value)throw Error(name); cases[name]=true; }
ck('txid_constant',eq(txid,D(base)));
ck('different_witness_ids',!eq(wtxid(good,sg),wtxid(fake,sf)));
ck('authentic_absent_burn',strict(good,sg,commit(good,sg)));
ck('unmined_signed_claim_breaks_naive',naive(fake,sf));
ck('unmined_signed_claim_rejected',!strict(fake,sf,commit(fake,sf)));
ck('no_root_substitution',!strict(fake,sf,commit(good,sg)));
ck('no_signature_substitution',!strict(good,sf,commit(good,sg)));
ck('existing_burn_not_absent',!naive(Buffer.from(JSON.stringify({slot:7,burn:1})),sign(Buffer.from(JSON.stringify({slot:7,burn:1})))));
const output={checks:cases,passed:Object.keys(cases).length,limits:['synthetic hash witness fixture','accepted commitments are mock Bitcoin chain state','fixed burn-state snapshot','no SHA-based Build/Open','no QPT test']};
console.log(JSON.stringify(output,null,2));
