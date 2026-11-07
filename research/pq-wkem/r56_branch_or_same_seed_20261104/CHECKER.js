'use strict';
const crypto=require('crypto');
const Q=16777259, DELTA=65536;
let assertions=0;
function check(p,msg){assertions++;if(!p)throw new Error(msg)}
function ring(n){
 const N=1<<n,mod=x=>((x%Q)+Q)%Q,zero=()=>Array(N).fill(0),one=()=>{let o=zero();o[0]=1;return o},v=i=>{let o=zero();o[1<<i]=1;return o};
 function mul(a,b){let c=zero();for(let i=0;i<N;i++)if(a[i])for(let j=0;j<N;j++)if(b[j])c[i|j]=mod(c[i|j]+a[i]*b[j]);return c}
 function fail(lits){let a=one();for(const [i,pos] of lits){let z=v(i);a=mul(a,pos?one().map((k,j)=>mod(k-z[j])):z)}return a}
 function pow(a,e){let t=1;while(e>0){if(e%2)t=mod(t*a);a=mod(a*a);e=Math.floor(e/2)}return t}
 function quotient(gs){let piv=new Map();for(const g of gs){let r=g.map(mod);for(;;){let j=r.findIndex(x=>x);if(j<0)break;if(!piv.has(j)){const inv=pow(r[j],Q-2);piv.set(j,r.map(x=>mod(x*inv)));break}let rr=piv.get(j),co=r[j];r=r.map((x,k)=>mod(x-co*rr[k]))}}
  let pivot=[...piv.keys()].sort((a,b)=>a-b),free=Array.from({length:N},(_,i)=>i).filter(i=>!piv.has(i));
  function P(x){let r=x.map(mod);for(const j of pivot)if(r[j]){let co=r[j],rr=piv.get(j);r=r.map((z,k)=>mod(z-co*rr[k]))}return free.map(i=>r[i])}
  function S(x){let y=zero();free.forEach((i,j)=>y[i]=x[j]);return y}
  return {rank:pivot.length,dim:free.length,P,S}
 }
 function ev(a,w){let x=0;for(let i=0;i<N;i++)if((i&w)===i)x=mod(x+a[i]);return x}
 function fixture(clauses){let fs=clauses.map(fail),mono=[];for(let i=0;i<N;i++)if(i.toString(2).replace(/0/g,'').length<=2){let x=zero();x[i]=1;mono.push(x)}
  let gs=[];for(let i=0;i<fs.length;i++)for(let j=i;j<fs.length;j++)gs.push(mul(fs[i],fs[j]));for(const f of fs)for(const z of mono)gs.push(mul(f,z));let base=quotient(gs);
  const witnesses=Array.from({length:N},(_,i)=>i).filter(w=>fs.every(f=>ev(f,w)===0));return {...base,witnesses,n,N}}
 return {N,mod,one,ev,fixture}
}
let state=0x9abcde81;function rand(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0}
function noise(N){return Array.from({length:N},()=>rand()%3-1)}
function enc(b,byte,e){let y=e.slice();y[0]+=DELTA*byte;return b.P(y)}
function decode(r,b,z,w){let a=r.ev(b.S(z),w),best=Number.MAX_SAFE_INTEGER,which=-1;for(let k=0;k<256;k++){let d=Math.min(r.mod(a-DELTA*k),r.mod(DELTA*k-a));if(d<best){best=d;which=k}}check(best<=r.N,'decoder radius');return which}
function hash(obj){return crypto.createHash('sha3-256').update(JSON.stringify(obj)).digest('hex')}
function transcript({capsules,domain,ctx,kbind,D,alpha,vk,related,selected,noiseReveals=[]}){
  const publicPart={domain,ctx,alpha,D,vk,capsules,related,selected,noiseReveals};
  return { ...publicPart,CK:hash({key:kbind,domain:'CK-v56',publicPart}),Aux:hash({key:kbind,domain:'Aux-v56',publicPart})};
}
const R4=ring(4);
const trueA=R4.fixture([[[0,true],[0,true],[0,true]]]); // z0=1
const trueB=R4.fixture([[[1,false],[1,false],[1,false]]]); // z1=0
const fA=R4.fixture([[[0,true],[0,true],[0,true]],[[0,false],[0,false],[0,false]]]);
const fB=R4.fixture([[[1,true],[1,true],[1,true]],[[1,false],[1,false],[1,false]]]);
const fC=R4.fixture([[[2,true],[2,true],[2,true]],[[2,false],[2,false],[2,false]]]);
const falseBranches=[fA,fB,fC], trueBranches=[trueA,trueB];
for(const b of trueBranches)check(b.witnesses.length===8,'8 genuine ORIGINAL witnesses each');
for(const b of falseBranches){check(b.witnesses.length===0,'genuine impossible ORIGINAL relation');check(b.P(R4.one()).every(x=>x===0),'public certified FALSE');check(b.dim>0,'nonempty quotient')}
check(Math.min(DELTA,Q-255*DELTA)>2*R4.N,'packing radius');
let openings=0;
for(let byte=0;byte<256;byte++){
 let e1=noise(R4.N),e2=noise(R4.N),z1=enc(trueA,byte,e1),z2=enc(trueB,byte,e2);
 for(const w of trueA.witnesses){check(decode(R4,trueA,z1,w)===byte,'branch A same precommitted byte');openings++}
 for(const w of trueB.witnesses){check(decode(R4,trueB,z2,w)===byte,'branch B same precommitted byte');openings++}
}
let coupled=0,adaptiveCoupled=0,leakedNoiseCoupled=0;
for(let trial=0;trial<256;trial++){
 const secretA=Array.from({length:12},()=>rand()%256),secretB=Array.from({length:12},()=>rand()%256);
 const sharedErr=Array.from({length:12},()=>noise(R4.N));
 // Each branch uses THE SAME errors, stronger correlation than independent noise.
 const build=(secret)=>falseBranches.map(b=>secret.map((k,j)=>enc(b,k,sharedErr[j])));
 const left=build(secretA),right=build(secretB);
 check(JSON.stringify(left)===JSON.stringify(right),'all same-secret certified FALSE branch capsules couple');coupled++;
 // Post-publication authorized reveal schedule; select based on first branch and D, not secret.
 const D='fixed-public-masked-native-signature-'+trial,alpha='honestly-derived-matrix-commit-'+trial,ctx='manifest|claim|utxo|branch|anchor|window|native-vk|path';
 const selected=[0,(left[0][0].reduce((s,x)=>s+x,trial+D.length)%2)+1];
 const view=(caps)=>transcript({capsules:caps,domain:'R56-OR',ctx,kbind:'known-to-simulator-'+trial,D,alpha,vk:'native-vk',related:'independently-seeded-other-claim',selected,noiseReveals: selected.map(i=>[i,sharedErr[0]])});
 check(JSON.stringify(view(left))===JSON.stringify(view(right)),'CK, Aux, adaptive reveal and leak-noise joint view');adaptiveCoupled++;leakedNoiseCoupled++;
}
// Counter-control: attaching one TRUE branch to the same unknown seed breaks this exact secrecy simulator.
const ee=Array(R4.N).fill(0),neg0=enc(trueA,0,ee),neg1=enc(trueA,1,ee);
check(JSON.stringify(neg0)!==JSON.stringify(neg1),'TRUE member invalidates all-FALSE source simulation');
// Full branch manifest must be part of the authenticated check; reordering modifies binding.
let b0=transcript({capsules:['a','b'],domain:'R56-OR',ctx:'claim1',kbind:'secret',D:'d',alpha:'a',vk:'v',related:[],selected:[0]});
let b1=transcript({capsules:['b','a'],domain:'R56-OR',ctx:'claim1',kbind:'secret',D:'d',alpha:'a',vk:'v',related:[],selected:[0]});
check(b0.CK!==b1.CK,'ordered branch manifest participates in real SHA3-256 checking-key tag');
const result={run:'R56-BRANCH-OR-SAME-SEED-20261104',assertions,code:'exact Node.js checker',q:Q,delta:DELTA,branches_true:trueBranches.map(x=>({witnesses:x.witnesses.length,quotient:x.dim})),branches_cert_false:falseBranches.map(x=>({quotient:x.dim,rank:x.rank})),genuine_original_openings:openings,same_seed_false_joint_couplings:coupled,adaptive_correlated_ck_aux_couplings:adaptiveCoupled,selective_noise_reveal_couplings:leakedNoiseCoupled,sourceopen_oracle:false,qpt_security_tested:false,hard_true_extraction:'UNPROVED'};
console.log(JSON.stringify(result,null,2));
