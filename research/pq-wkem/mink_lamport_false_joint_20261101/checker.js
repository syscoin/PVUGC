// Exact executed standalone JavaScript algebra checker. Node: node checker.js
console.log(JSON.stringify((function checker(){
"use strict";
let checks=0;
const ok=(v,m)=>{if(!v)throw Error(m);++checks;};
const map=(A,s)=>A.reduce((v,r,i)=>v^((s>>i&1)?r:0),0);
const dot=(a,b)=>{let x=a&b,p=0;while(x){p^=x&1;x>>=1;}return p;};
function solve(A,y){
 const piv=new Map(),ker=[];
 A.forEach((row,i)=>{let x=row,mask=1<<i;
  while(x){const p=31-Math.clz32(x);if(!piv.has(p)){piv.set(p,[x,mask]);break;}
   const [q,v]=piv.get(p);x^=q;mask^=v;}
  if(!x)ker.push(mask);
 });
 let sol=0,x=y;
 while(x){const p=31-Math.clz32(x);if(!piv.has(p))return null;
  const [q,v]=piv.get(p);x^=q;sol^=v;}
 return {sol,ker};
}
const T=[6],F=[6,7],F3=[6,7,6];
for(const A of [T,F,F3]){
 const image=new Set(Array.from({length:1<<A.length},(_,s)=>map(A,s)));
 for(let y=0;y<8;y++){
  const r=solve(A,y);ok((r!==null)===image.has(y),'image membership');
  if(r){ok(map(A,r.sol)===y,'particular solution');
   const fiber=new Set();for(let mask=0;mask<(1<<r.ker.length);mask++){
    let x=r.sol;for(let j=0;j<r.ker.length;j++)if(mask>>j&1)x^=r.ker[j];
    fiber.add(x);
   }
   const actual=new Set(Array.from({length:1<<A.length},(_,s)=>s).filter(s=>map(A,s)===y));
   ok(fiber.size===actual.size&&[...fiber].every(v=>actual.has(v)),'affine fiber support');
  }
 }
}
const witnesses=A=>[[0,0],[0,1],[1,0],[1,1]].filter(z=>A.every(row=>!dot(row,1|(z[0]<<1)|(z[1]<<2))));
ok(JSON.stringify(witnesses(T))===JSON.stringify([[0,0],[1,1]]),'two true witnesses');
ok(witnesses(F).length===0,'false relation');
const delta=solve(F,1).sol;ok(map(F,delta)===1,'refutation delta');
for(let m=0;m<2;m++){
 const actual=new Set(),simulated=new Set();
 for(let s=0;s<4;s++){
  const c=map(F,s)^m,zero=s^(m?delta:0);
  actual.add(c+','+zero);simulated.add(map(F,s)+','+s);
 }
 ok(actual.size===4&&[...actual].every(t=>simulated.has(t)),'exact false coin distribution');
}
let triples=0;
for(let keybit=0;keybit<2;keybit++)for(let a=0;a<2;a++)for(let b=0;b<2;b++){
 const ms=[a,b,a^b^keybit];
 for(let s0=0;s0<4;s0++)for(let s1=0;s1<4;s1++)for(let s2=0;s2<4;s2++){
  const ss=[s0,s1,s2],C=ss.map((s,i)=>map(F,s)^ms[i]);
  for(let i=0;i<3;i++){
   const z=ss[i]^(ms[i]?delta:0);
   ok(C[i]===map(F,z),'actual coins produce zero-mode');
   ok(solve(F,C[i])!==null,'compact certificate checks image');
  }
  triples++;
 }
 const v0=1,v1=7;
 for(let s0=0;s0<2;s0++)for(let s1=0;s1<2;s1++)for(let s2=0;s2<2;s2++){
  const ss=[s0,s1,s2],C=ss.map((s,i)=>map(T,s)^ms[i]);
  ok(C.reduce((r,c)=>r^dot(c,v0),0)===keybit,'witness 00 same bit');
  ok(C.reduce((r,c)=>r^dot(c,v1),0)===keybit,'witness 11 same bit');
 }
}
for(const pair of [[0,1],[0,2],[1,2]])for(let k=0;k<2;k++){
 const seen=new Map();for(let a=0;a<2;a++)for(let b=0;b<2;b++){
  const m=[a,b,a^b^k],x=m[pair[0]]+','+m[pair[1]];
  seen.set(x,(seen.get(x)||0)+1);
 }
 ok(seen.size===4&&[...seen.values()].every(v=>v===1),'two-share independence');
}
return {name:"MINK-LAMPORT-FALSE algebra",checks,triples,refutation_delta:delta,certificate_bits:F.length,key_bits:131072,scope:"small F2 fixture, no QPT hardness claim"};
})(),null,2));
