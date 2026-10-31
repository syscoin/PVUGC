// Self-contained exact integer checker for the two-source XOR-shared Fourier release.
// Only finite-algebra identities are tested; no PQ hardness/security experiment.
'use strict';
const assert = (p, msg) => { if (!p) throw Error(msg); checks++; };
let checks = 0;
const rhoNumerator = 2, rhoDenominator = 3;
// One bit: true source BSC(1/6); false source has P0=P1=uniform.
function oneBitNumerator(observed, encoded, isTrue) {
  if (!isTrue) return 3;
  return observed === encoded ? 5 : 1;
}
function twoBitNumerator(q, c, isTrue) {
  let n = 1;
  for (let j=0; j<2; j++) n *= oneBitNumerator((q>>j)&1,(c>>j)&1,isTrue);
  return n; // conditional probability n/36.
}
function view(K, missing, trueMask, nullMissing) {
  // Each sampled other share, dither pair, and public quotient pair is in the view.
  // The target share is K XOR the other share, but the null target does not use it.
  const output = new Map();
  for(let other=0;other<4;other++) for(let d0=0;d0<4;d0++) for(let d1=0;d1<4;d1++) {
    const shares = missing===0 ? [K^other,other] : [other,K^other];
    const code = [shares[0]^d0,shares[1]^d1]; // Identity code, only for distribution check.
    for(let q0=0;q0<4;q0++) for(let q1=0;q1<4;q1++) {
      const c0 = nullMissing && missing===0 ? 0 : code[0];
      const c1 = nullMissing && missing===1 ? 0 : code[1];
      const n=twoBitNumerator(q0,c0,(trueMask&1)!==0)*twoBitNumerator(q1,c1,(trueMask&2)!==0);
      const key=[other,d0,d1,q0,q1].join(',');
      output.set(key,n); // Full probability: n/(36*36*4*4*4).
    }
  }
  return output;
}
function sameMap(a,b,label){
  assert(a.size===b.size,label+' same support size');
  for(const [key,n] of a)assert(b.get(key)===n,label+' '+key);
}
for (let missing=0;missing<2;missing++) for(let K=0;K<4;K++) {
  // One false ORIGINAL source, regardless of whether the other is true.
  let isTrueOther = 1<<(1-missing);
  sameMap(view(K,missing,isTrueOther,false),view(K,missing,isTrueOther,true),
          'false full joint law');
  // Even when the missing source is true, replacing its encrypted columns by
  // P0 yields a K-independent native-null public view (conditioned on pk=K&1).
  const bothTrue=3;
  sameMap(view(K,missing,bothTrue,true),view(K^2,missing,bothTrue,true),
          'native null K independence at equal toy pk');
}
// Check that all possible paired shares give the same precommitted K.
for(let K=0;K<4;K++)for(let other=0;other<4;other++)for(let missing=0;missing<2;missing++){
  const a=missing===0?K^other:other, b=missing===0?other:K^other;
  assert((a^b)===K,'same K for all valid witnesses after exact opening');
}
// Threefold majority: exact weighted probability of XOR-decoding error for two
// independent true-source shares, each BSC(1/6), is 100/729.
let errorWeight=0,totalWeight=0;
for(let e0=0;e0<8;e0++)for(let e1=0;e1<8;e1++){
  const wt=(e)=>((e&1)!==0)+((e&2)!==0)+((e&4)!==0);
  let w0=wt(e0),w1=wt(e1),w=5**(6-w0-w1);
  const err=Number(w0>=2)^Number(w1>=2);
  errorWeight+=err*w;totalWeight+=w;
  assert(err===0||err===1,'xor error is Boolean');
}
assert(totalWeight===6**6,'total channel mass');
assert(errorWeight*729===100*totalWeight,'exact XOR majority error 100/729');
// One-reflection Fourier extraction for an arbitrary deterministic success
// predicate f(y_target,y_other). The OTHER source is part of joint public view.
for(let f=0;f<16;f++)for(let bitOther=0;bitOther<2;bitOther++){
  const nOther=bitOther===0?[5,1]:[1,5];
  const A=[0,1].map(y=>((f>>(1+2*y))&1)-((f>>(0+2*y))&1));
  const gapNine=nOther[0]*A[0]+nOther[1]*A[1];
  const extSix=nOther[0]*A[0]**2+nOther[1]*A[1]**2;
  // gap=gapNine/9; extraction prob=extSix/6;
  // gap^2 <= rho^2*pExt <=> gapNine^2<=6*extSix.
  assert(gapNine**2<=6*extSix,'exact joint reflection extractor inequality');
}
const result={record:'and-shares-fourier-20261027',kind:'exact finite-algebra only',
  assertions:checks,sourceCount:2,keyBits:2,
  checkedFalseFullViews:8,checkedNativeNullViews:8,
  majorityXorError:'100/729',
  expectedScope:'No quantum hardness or native signature implementation tested'};
console.log(JSON.stringify(result,null,2));
