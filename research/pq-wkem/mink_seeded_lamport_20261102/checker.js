// MINK-SLSEED exact signed-XOR algebra checker. Test-only deterministic coins;
// actual SHAKE256/SHA384 signing is tested separately in checker.py.
'use strict';
let checks=0;
function need(x,msg){if(!x)throw Error(msg);checks++;}
function parity(x){let p=0;while(x){p^=1;x&=x-1;}return p;}
function dot(x,y){return parity(x&y);}
function rows(edges){return edges.map(([u,v,b])=>b^(1<<(u+1))^(1<<(v+1)));}
function col(A,s){let x=0;for(let i=0;i<A.length;i++)if((s>>i)&1)x^=A[i];return x;}
function span(A,C){for(let s=0;s<(1<<A.length);s++)if(col(A,s)===C)return true;return false;}
const T=rows([[0,1,0],[1,2,0]]), F=rows([[0,1,0],[0,1,1]]);
const delta=3;
need(col(F,delta)===1,'false certificate');
need(!span(T,1),'no false certificate for true source');
const witnesses=[1,15];
for(let w of witnesses)for(let row of T)need(dot(row,w)===0,'ORIGINAL witness');
let state=0x510d02;
function randBit(){state=(Math.imul(state,1664525)+1013904223)>>>0;return state&1;}
function rand2(){return (randBit()|(randBit()<<1));}
const seed=Array.from({length:256},()=>randBit());
let C=[];let ms=[];
for(let i=0;i<256;i++){
 const m0=randBit(),m1=randBit(),m2=seed[i]^m0^m1;
 let local=[];
 for(let m of [m0,m1,m2]){let s=rand2(),c=col(T,s)^m;local.push(c);ms.push(m);need(c===(col(T,s)^m),'build');}
 C.push(...local);
}
for(let w of witnesses)for(let i=0;i<256;i++)need((dot(C[3*i],w)^dot(C[3*i+1],w)^dot(C[3*i+2],w))===seed[i],'all witnesses same seed');
const openedPairs=[[0,1],[0,2],[1,2]];
const support=[];
function distrib(secret,opened){
 const tally=new Map();
 for(let m0=0;m0<2;m0++)for(let m1=0;m1<2;m1++)for(let s0=0;s0<4;s0++)for(let s1=0;s1<4;s1++)for(let s2=0;s2<4;s2++){
  let m=[m0,m1,secret^m0^m1],s=[s0,s1,s2],cs=s.map((v,j)=>col(F,v)^m[j]);
  let view=[...cs,...opened.flatMap(j=>[j,m[j],s[j]])].join(',');
  tally.set(view,(tally.get(view)||0)+1);
 }
 return tally;
}
for(let pair of openedPairs){
 const a=distrib(0,pair),b=distrib(1,pair);
 need(a.size===b.size,'selective support');
 for(let [view,count] of a)need(b.get(view)===count,'full correlated two-lane equality');
 support.push(a.size);
}
for(let i=0;i<256;i++){
 need((ms[3*i]^ms[3*i+1]^ms[3*i+2])===seed[i],'correct three-lane mask');
 for(let j=0;j<3;j++){
  const sr=rand2(),m=randBit(),Cs=col(F,sr),sReal=sr^(m?delta:0);
  need((col(F,sReal)^m)===Cs,'false unknown-seed re-opening');
 }
}
const bitsOld=3*768*48*8*4,bitsSeed=3*256*4;
need(bitsOld/bitsSeed===1152,'bitpacked compression factor');
console.log(JSON.stringify({run:'MINK-SLSEED-20261102',checks,exact_selective_support:support,compression:bitsOld/bitsSeed,old_bytes:bitsOld/8,new_bytes:bitsSeed/8,security:'algebra only, no QPT claim'},null,2));
