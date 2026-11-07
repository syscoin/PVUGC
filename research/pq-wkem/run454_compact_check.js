'use strict';
// Run 454 finite diagnostic. Ed25519 is NOT PQ. No WE/obfuscator is instantiated.
const C = require('node:crypto');
let checks = 0;
function ok(x) { if (!x) throw new Error('assertion ' + (checks + 1)); checks++; }
function h(...a) { const x = C.createHash('sha256'); for (const v of a) { const b=Buffer.from(String(v)); x.update(Buffer.from([b.length>>8,b.length&255])); x.update(b); } return x.digest(); }
function env(bits, m, ctx) {
  const N=2**bits, scores=Array.from({length:N},(_,i)=>[h('marked',ctx,i).toString('hex'),i]);
  scores.sort((a,b)=>a[0].localeCompare(b[0]));
  const accept=new Set(scores.slice(0,m).map(p=>p[1]));
  const seed=h('non-pq-key',ctx);
  const priv=C.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
  const pub=C.createPublicKey(priv), msg=h('branch',ctx);
  const release=s=>accept.has(s)?C.sign(null,msg,priv):null;
  const verify=(sig, text=msg, key=pub)=>!!sig&&C.verify(null,text,key,sig);
  return {N,m,accept,pub,msg,release,verify};
}
function grover(N, marked, iterations) {
  let a=Array(N).fill(1/Math.sqrt(N));
  for(let t=0;t<iterations;t++){
    for(const j of marked)a[j]=-a[j];
    const mean=a.reduce((x,y)=>x+y,0)/N;
    a=a.map(v=>2*mean-v);
  }
  return {p:[...marked].reduce((s,j)=>s+a[j]*a[j],0),norm:a.reduce((s,v)=>s+v*v,0)};
}
let signatureCases=0, coherentCases=0;
for(const [b,m] of [[6,1],[6,5],[8,1],[8,16],[10,32]]){
  const a=env(b,m,'run454/'+b+'/'+m);
  ok(a.accept.size===m);
  let hits=0, seen=new Set();
  for(let s=0;s<a.N;s++){
    const sig=a.release(s); if(a.verify(sig)){hits++;seen.add(sig.toString('hex'));}
  }
  ok(hits===m);ok(seen.size===1); // same native signing key/signature for all good states
  let found=null;for(let s=0;s<a.N;s++){const sig=a.release(s);if(a.verify(sig)){found=sig;break;}}
  ok(found!==null);ok(!a.verify(found,h('wrong branch',b,m)));
  signatureCases++;
}
for(let b=3;b<=7;b++)for(const m of [1,2,3,4]){
  const N=2**b;if(m>N/4)continue;
  const marked=new Set(Array.from({length:m},(_,i)=>(i*13+7)%N));
  ok(marked.size===m);
  const theta=Math.asin(Math.sqrt(m/N));
  const j=Math.max(0,Math.round(Math.PI/(4*theta)-.5));
  for(const t of [...new Set([0,1,2,j])]){
    const r=grover(N,marked,t), want=Math.sin((2*t+1)*theta)**2;
    ok(Math.abs(r.p-want)<1e-11);ok(Math.abs(r.norm-1)<1e-11);
  }
  coherentCases++;
}
ok((256-64)/2===96);ok((320-64)/2===128);
console.log(JSON.stringify({run:454,checks,signatureCases,coherentCases,description:'public small-frontier search; synthetic opaque release; Ed25519 non-PQ; no construction/security proof'},null,2));
