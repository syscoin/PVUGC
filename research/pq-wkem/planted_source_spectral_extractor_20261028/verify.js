'use strict';
// Offline finite checks only; not a QPT or native-SLH security test.
let n=0;
function ck(b,label){if(!b)throw new Error(label);n++;}
const q=65537n,M=1024n,k=32n,h=128n,g=257n;
const base=q/g, ell=33n;
ck(base===255n && base**32n < 2n**256n && 2n**256n <= base**33n,'radix');
ck(g*(base-1n)<q && q-g*(base-1n)>2n*h,'cyclic final gap');
const numer=(q**(k-1n)-1n)*q**M;
const denom=(q**(M-1n)-1n)*3n**M;
ck(numer*2n**1100n<denom,'expected offspan Fourier energy <2^-1100');
ck(numer*2n**(512n+580n)<denom,'Markov bad source probability <2^-580');
const smallQ=5,smallM=4,root=Array.from({length:5},(_,i)=>2*Math.PI*i/5);
const eSq=Array.from({length:5},(_,i)=>((1+2*Math.cos(root[i]))/3)**2);
const w=[1,1,0,0];
function weight(z){return z.reduce((a,v)=>a*eSq[v],1);}
function eq(a,b,tol=1e-9){return Math.abs(a-b)<tol;}
let lines=[],all=0,total=0;
for(let a=0;a<5;a++)for(let b=0;b<5;b++)for(let c=0;c<5;c++){
 if(!a&&!b&&!c)continue;
 const first=[a,b,c].find(x=>x!==0);
 let inv=[0,1,3,2,4][first];
 if(a*inv%5!==a || b*inv%5!==b || c*inv%5!==c)continue;
 lines.push([0,a,b,c]);
}
ck(lines.length===31,'q5 quotient lines');
let es=0;
for(const v of lines){
 let cur=0;
 for(let d=1;d<5;d++)for(let c=0;c<5;c++){
  const z=w.map((x,i)=>(c*x+d*v[i])%5);cur+=weight(z);
 }
 es+=cur;
}
const probability=(5-1)/(5**(smallM-1)-1);
const expected=probability*((5/3)**smallM-[0,1,2,3,4].reduce((s,c)=>s+weight(w.map(x=>c*x%5)),0));
ck(eq(es/31,expected),'planted offspan Fourier expectation');
let allspaces=0,esFalse=0;
for(let a=0;a<smallM;a++)for(let b=a+1;b<smallM;b++){
 let free0=[],free1=[];
 for(let i=a+1;i<smallM;i++)if(i!==b)free0.push(i);
 for(let i=b+1;i<smallM;i++)free1.push(i);
 for(let t0=0;t0<5**free0.length;t0++)for(let t1=0;t1<5**free1.length;t1++){
  let r0=[0,0,0,0],r1=[0,0,0,0];r0[a]=1;r1[b]=1;
  let v=t0;for(const j of free0){r0[j]=v%5;v=Math.floor(v/5);}
  v=t1;for(const j of free1){r1[j]=v%5;v=Math.floor(v/5);}
  let energy=0;
  for(let c=0;c<5;c++)for(let d=0;d<5;d++)if(c||d)
   energy+=weight(r0.map((x,i)=>(c*x+d*r1[i])%5));
  esFalse+=energy;allspaces++;
 }
}
ck(allspaces===806,'all q5 two-dimensional subspaces');
ck(eq(esFalse/allspaces,(5**2-1)/(5**smallM-1)*((5/3)**smallM-1)),'false Fourier expectation');
// Exact finite Fourier-list: oracle only returns success f(p), never witness.
const pts=[];for(let a=0;a<5;a++)for(let b=0;b<5;b++)for(let c=0;c<5;c++)for(let d=0;d<5;d++)pts.push([a,b,c,d]);
const response=pts.map(p=>((p[0]+p[1])%5<=1 || (p[0]+p[1])%5===4)?1:0);
const chars=new Map();
for(const z of pts){let real=0,imag=0;
 for(let i=0;i<pts.length;i++)if(response[i]){
  const phase=pts[i].reduce((s,x,j)=>s+x*z[j],0)%5;
  real+=Math.cos(root[phase]);imag-=Math.sin(root[phase]);
 }
 real/=pts.length;imag/=pts.length;
 chars.set(z.join(','),real*real+imag*imag);
}
const tau=0.20;let prefixes=[[]];
for(let t=1;t<=smallM;t++){
 let next=[];
 for(const pre of prefixes)for(let d=0;d<5;d++){
  let target=pre.concat(d),energy=0;
  for(const z of pts)if(target.every((v,j)=>v===z[j]))energy+=chars.get(z.join(','));
  if(energy>=tau*tau/2)next.push(target);
 }
 prefixes=next;ck(prefixes.length<=Math.floor(2/tau**2),'Parseval list size');
}
let recovered=false;
for(const z of prefixes){if(!z[0])continue;
 const inv=[0,1,3,2,4][z[0]];
 const cand=z.map(x=>x*inv%5);
 if(cand.join(',')===w.join(','))recovered=true;
}
ck(recovered,'ORIGINAL witness extracted without representation returned');
console.log(JSON.stringify({status:'PASS',checks:n,q:Number(q),M:Number(M),kernel_dimension:Number(k),witness_weight:Number(h),radix:Number(base),columns:Number(ell),toy_planted_subspaces:lines.length,toy_unplanted_subspaces:allspaces,toy_extractor_recovered:recovered,hardness_proved:false}));
