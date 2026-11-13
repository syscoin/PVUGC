'use strict';
// Run 534: polynomial symbolic leakage of known-baseline release in clear OBDDs.
// Research falsifier; this does not implement a real WKEM or PQ endpoint.
const assert = require('assert');
let state = 53415 >>> 0;
function rnd() { state = (Math.imul(state,1664525)+1013904223)>>>0; return (state>>>16) & 1; }
function bits(n) { let s=''; for(let i=0;i<n;i++) s+=rnd(); return s; }
class BDD {
  constructor() { this.ns=[null,null]; this.memo=new Map(); }
  mk(v,l,h) {
    if(l===h) return l;
    const k=v+','+l+','+h;
    if(this.memo.has(k)) return this.memo.get(k);
    const j=this.ns.length; this.ns.push([v,l,h]);this.memo.set(k,j);return j;
  }
  equalPrefix(w,n) {
    assert(w.length<=n);
    let p=1;
    for(let i=w.length-1;i>=0;i--) p=w[i]==='0'?this.mk(i,p,0):this.mk(i,0,p);
    return p;
  }
  negate(root) {
    const seen=new Map([[0,1],[1,0]]);
    const walk=(p)=>{if(seen.has(p))return seen.get(p);
      const [v,l,h]=this.ns[p];let q=this.mk(v,walk(l),walk(h));seen.set(p,q);return q;};
    return walk(root);
  }
  evaluate(root,s) {let p=root;while(p>1){const [v,l,h]=this.ns[p];p=s[v]==='0'?l:h;}return p;}
  find(root,goal,n) {
    const can=new Map([[0,goal===0],[1,goal===1]]);
    const walk=(p)=>{if(can.has(p))return can.get(p);
      const [v,l,h]=this.ns[p];let a=walk(l)||walk(h);can.set(p,a);return a;};
    if(!walk(root))return null;
    const out=new Array(n).fill('0');let p=root;
    while(p>1){const [v,l,h]=this.ns[p];if(can.get(l)){out[v]='0';p=l;}
      else{assert(can.get(h));out[v]='1';p=h;}}
    return out.join('');
  }
}
let total=0,recoveries=0,opened=0,multi=0,largest=0;
const widths=[256,512,1024,2048],examples=[];
for(const kind of ['needle','prefix','random_tape']) for(const n of widths) {
  for(let j=0;j<6;j++) {
    const w=bits(n),K=bits(256),B=bits(256);
    assert.notEqual(K,B);
    const bdd=new BDD();const len=kind==='needle'?n:kind==='prefix'?n/4:n/2;
    const success=bdd.equalPrefix(w.slice(0,len),n),no=bdd.negate(success);
    const roots=[...K].map((c,i)=>c===B[i]?Number(c):B[i]==='0'?success:no);
    let found='',some=null;
    for(let i=0;i<256;i++) {
      const opposite=1-Number(B[i]),s=bdd.find(roots[i],opposite,n);
      if(s===null)found+=B[i];
      else{found+=opposite;if(some===null)some=s;}
    }
    assert.equal(found,K);assert(some!==null);assert.equal(bdd.evaluate(success,some),1);
    assert.equal(roots.map(root=>bdd.evaluate(root,some)).join(''),K);
    if(len<n){const alt=w.slice(0,-1)+(w.at(-1)==='0'?'1':'0');
      assert.equal(bdd.evaluate(success,alt),1);multi++;}
    total++;recoveries++;opened++;largest=Math.max(largest,bdd.ns.length);
    if(j===0)examples.push({kind,width:n,nodes:bdd.ns.length,seed_bits:256});
  }
}
let junkFailures=0;
for(let j=0;j<80;j++) {
  const needle=(j*17)&63,key=(j*103)&255;
  const outs=Array.from({length:64},(_,s)=>s===needle?key:((s*73)^(s>>1)^0xA5)&255);
  let extremum=0;for(let bit=0;bit<8;bit++)
    if(outs.some(x=>((x>>bit)&1)!==0))extremum|=1<<bit;
  if(extremum!==key)junkFailures++;
}
assert(junkFailures>=75);
const report={run:534,status:'PASS',symbolic_cases:total,exact_key_recoveries:recoveries,
  recovered_accepted_inputs:opened,distinct_valid_inputs_same_key:multi,
  max_bdd_nodes:largest,seed_bits:256,widths,examples,
  junk_negative_controls:80,junk_nonrecoveries:junkFailures,
  scope:'clear per-output OBDDs, known failure baseline and freely selectable inputs; no security conclusion for composed hidden-frame chips'};
console.log(JSON.stringify(report,null,2));
