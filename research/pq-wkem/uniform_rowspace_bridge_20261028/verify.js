// Offline uniform-rowspace SOURCE checker; finite algebra ONLY, not QPT/native security.
const q=257;let assertions=0;
function ok(x,label){if(!x)throw Error(label);assertions++}
const mod=(x,p)=>((x%p)+p)%p;
function mask(G,y,p){return G[0].map((_,j)=>mod(G.reduce((s,row,i)=>s+row[j]*y[i],0),p))}
function capsule(G,y,e,d,g,p){return mask(G,y,p).map((x,j)=>mod(x+e[j]+(j===0?g*d:0),p))}
const Gfalse=[[1,0,0],[0,1,0]],lambda=[1,0];
ok(JSON.stringify(mask(Gfalse,lambda,7))===JSON.stringify([1,0,0]),'certificate');
const original=new Map();
for(let d=0;d<4;d++){
 const counts=new Map();
 for(let x=0;x<7;x++)for(let y=0;y<7;y++)
  for(let e0=-1;e0<=1;e0++)for(let e1=-1;e1<=1;e1++)for(let e2=-1;e2<=1;e2++){
   const e=[e0,e1,e2];const p=capsule(Gfalse,[x,y],e,d,2,7).join(',');
   const shifted=capsule(Gfalse,[mod(x+2*d,7),y],e,0,2,7).join(',');
   ok(p===shifted,'full-vector certified-false shift');
   counts.set(p,(counts.get(p)||0)+1);
  }
 ok([...counts.values()].reduce((a,b)=>a+b,0)===7*7*27,'full law count');
 if(d===0)for(const [k,v] of counts)original.set(k,v);
 else ok(counts.size===original.size&&[...counts].every(([k,v])=>original.get(k)===v),'same whole distribution');
}
let state=20261028;function rand(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0}
function randomBytes(){return Uint8Array.from({length:32},()=>rand()%256)}
const xor=(...sets)=>Uint8Array.from({length:32},(_,i)=>sets.reduce((v,s)=>v^s[i],0));
const asInt=b=>b.reduce((v,x)=>(v<<8n)+BigInt(x),0n);
function toBytes(z){return Uint8Array.from({length:32},(_,i)=>Number((z>>BigInt(8*(31-i)))&255n))}
const Gtrue=[[1,-1,-1]],ws=[[1,1,0],[1,0,1]];
for(const w of ws)ok(mask(Gtrue,[1],q).reduce((v,a,i)=>v+a*w[i],0)%q===0,'true kernel');
let ell=0,cap=1n;while(cap<(1n<<256n)){cap*=51n;ell++}ok(ell===46,'radix capacity');
for(let trial=0;trial<12;trial++){
 const K=randomBytes(),U=randomBytes(),Z=randomBytes();
 const D=xor(U,Z),V=xor(K,U);
 let zz=asInt(Z);const digits=[];
 for(let j=0;j<ell;j++){digits.push(Number(zz%51n));zz/=51n}ok(zz===0n,'pad encoded');
 const all=ws.map(()=>[]);
 for(const d of digits){
  const y=[rand()%q],err=Array.from({length:3},()=>rand()%3-1);
  const p=capsule(Gtrue,y,err,d,5,q);
  for(let t=0;t<ws.length;t++){
   const phase=mod(p.reduce((s,x,i)=>s+x*ws[t][i],0),q);
   const possible=[];
   for(let a=0;a<51;a++){const v=mod(phase-5*a,q);if(Math.min(v,q-v)<=2)possible.push(a)}
   ok(possible.length===1&&possible[0]===d,'same digit');all[t].push(d);
  }
 }
 for(const ds of all){let z=0n;for(let i=ell-1;i>=0;i--)z=z*51n+BigInt(ds[i]);
  ok(asInt(xor(D,V,toBytes(z)))===asInt(K),'SAME native-seed mock');}
}
// Exact rational union bound on rank failure: <= (q^r-1)/(q^(r+8)*(q-1)).
for(const [r,L] of [[230,27],[63,24]]){
 const Q=65537n,R=BigInt(r),N=R+8n;
 ok(BigInt(L)*(Q**R-1n)*(1n<<128n)<Q**N*(Q-1n),'statistical total < 2^-128');
}
console.log(JSON.stringify({result:'PASS',assertions,restrictedFalseWholeView:'EXACT',
 fullSeedTrials:12,distinctOriginalWitnesses:2,radix:51,columns:46,
 rankBridgeQ:65537,rankBridgeExamples:[[230,27],[63,24]],
 genericHardTrueRecoveryProved:false,nativePQTest:false}));
