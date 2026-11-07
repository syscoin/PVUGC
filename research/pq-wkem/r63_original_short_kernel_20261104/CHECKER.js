'use strict';
// R63 offline deterministic algebra-and-release checker. Finite toy checks, NOT a QPT proof.
const crypto = require('crypto');
const RUN='R63-ORIGINAL-SHORT-KERNEL-20261104';
let seed=0x630063,checks=0;
function ok(x,msg){if(!x)throw Error(`assertion ${checks}: ${msg}`);checks++;}
function rand(){seed=(seed+0x6D2B79F5)>>>0;let x=seed;x=Math.imul(x^(x>>>15),x|1);x^=x+Math.imul(x^(x>>>7),x|61);return (x^(x>>>14))>>>0;}
function hash(...a){return crypto.createHash('sha256').update(a.map(String).join('|')).digest('hex');}
function pad(k,n){return crypto.createHash('shake256',{outputLength:n}).update('toy-seed|'+k).digest();}
function mod(x,q){return ((x%q)+q)%q;}
function litTrue(l,w){return l>0?w[l-1]===1:w[-l-1]===0;}
function sat(clauses,w){return clauses.every(cl=>cl.some(l=>litTrue(l,w)));}
function compiler(nvar,clauses){
 const c=clauses.length,N=1+nvar+c,m=1+2*nvar+3*c,n=nvar+2*c;
 const A=Array.from({length:m},()=>Array(n).fill(0));
 for(let i=0;i<nvar;i++){A[0][i]=-1; A[1+2*i][i]=1;A[2+2*i][i]=1;}
 for(let j=0;j<c;j++){
  const sc=nvar+2*j,sv=sc+1,base=1+2*nvar+3*j;
  A[0][sc]=-1;A[0][sv]=-4;
  for(let z=0;z<3;z++){A[base+z][sc]=1;A[base+z][sv]=z+1;}
  for(const l of clauses[j]){const row=1+2*(Math.abs(l)-1)+(l>0?0:1);A[row][sv]++;}
 }
 return {A,nvar,clauses,N,m,n};
}
function vector(C,w,relaxed){
 const r=Array(C.m).fill(0);r[0]=1;
 for(let i=0;i<C.nvar;i++)r[1+2*i+(w[i]===1?0:1)]=1;
 for(let j=0;j<C.clauses.length;j++){
  const count=C.clauses[j].filter(l=>litTrue(l,w)).length,idx=1+2*C.nvar+3*j;
  if(count===0){ok(relaxed,'unmet clause in genuine witness');r[idx+1]=-1;r[idx+2]=2;}
  else r[idx+3-count]=1;
 }
 return r;
}
function kernel(C,r,q){return Array.from({length:C.n},(_,j)=>mod(r.reduce((s,b,i)=>s+b*C.A[i][j],0),q)).every(v=>v===0);}
function l1(r){return r.reduce((a,b)=>a+Math.abs(b),0);}
function bits(v){return Array.from({length:16},(_,j)=>(v>>>(15-j))&1);}
function number(b){return b.reduce((a,x)=>a*2+x,0);}
function encode(C,K,KB,q,delta){
 const pairs=[...bits(K),...bits(KB)].map(bit=>{
  const s=Array.from({length:C.n},()=>rand()%q),e=Array.from({length:C.m},()=>rand()%3-1);
  const y=C.A.map((row,i)=>mod(row.reduce((a,x,j)=>a+x*s[j],e[i]),q));
  return {y,cap:y.map((v,i)=>mod(v+(i===0?delta*bit:0),q))};
 });
 return {Y:pairs.map(x=>x.y),caps:pairs.map(x=>x.cap)};
}
function recover(C,caps,r,q,delta){return number(caps.slice(0,16).map(v=>open(v,r,q,delta))) * 65536 + number(caps.slice(16).map(v=>open(v,r,q,delta)));}
function open(v,r,q,delta){const z=mod(v.reduce((a,x,i)=>a+x*r[i],0),q);let d0=Math.min(z,q-z), d1=mod(z-delta,q);d1=Math.min(d1,q-d1);ok(d0!==d1,'ambiguous opening');return d1<d0?1:0;}
function originalWitnesses(C){const out=[];for(let a=0;a<(1<<C.nvar);a++){
 const w=Array.from({length:C.nvar},(_,i)=>(a>>i)&1);if(sat(C.clauses,w))out.push(w);
 }return out;}
function allOneHot(C){let count=0;const c=C.clauses.length,nv=C.nvar;for(let vm=0;vm<(1<<nv);vm++){
 const w=Array.from({length:nv},(_,i)=>(vm>>i)&1);
 for(let sm=0;sm<3**c;sm++){
  const r=Array(C.m).fill(0);r[0]=1;for(let i=0;i<nv;i++)r[1+2*i+(w[i]===1?0:1)]=1;
  let z=sm;for(let j=0;j<c;j++){r[1+2*nv+3*j+(z%3)]=1;z=Math.floor(z/3);}
  ok(l1(r)===C.N,'short one-hot norm');if(kernel(C,r,256)){
    ok(sat(C.clauses,w),'spurious short one-hot kernel');count++;
  }
 }
 }return count;}
function runCase(label,nvar,clauses,trialCount){
 const C=compiler(nvar,clauses),valid=originalWitnesses(C),q=1<<Math.ceil(Math.log2(Math.max(8*C.N+1,8*(C.N+2)+1))),delta=2*(C.N+2)+1;
 ok(q>8*C.N&&q>2*(delta+C.N+2),'modular spacing');
 const countShort=allOneHot(C);
 ok((countShort>0)===(valid.length>0),'exact satisfiability equivalence');
 let validOpens=0, falseBypasses=0, fullViewCouplings=0;
 for(const w of valid){const r=vector(C,w,false);ok(kernel(C,r,q),'original witness kernel');ok(l1(r)===C.N,'original witness length');}
 const input=Array.from({length:nvar},(_,i)=>i===0?1:0);
 let h=null;
 if(valid.length===0){h=vector(C,input,true);ok(kernel(C,h,q),'FALSE signed kernel');ok(l1(h)===C.N+2,'FALSE near-short kernel');ok(h.some(x=>x<0||x>1),'FALSE is not an accepted binary witness');}
 for(let t=0;t<trialCount;t++){
  const K=rand()%65536,KB=rand()%65536,{caps,Y}=encode(C,K,KB,q,delta);
  const sigma=Buffer.from(Array.from({length:48},()=>rand()%256)),D=Buffer.from(sigma.map((v,j)=>v^pad(K,48)[j]));
  const base=JSON.stringify({label,clauses,A:C.A,caps,D:D.toString('hex'),path:'claim/UTXO/window/vk'});
  const CK=hash('CK',KB,base),Aux=hash('Aux',KB,CK,base);
  const i=t%32,mu=[...bits(K),...bits(KB)][i];
  const sim=Y[i].map((y,j)=>mod(y+(j===0?delta*mu:0),q));
  const restored=caps.slice();restored[i]=sim;
  const simBase=JSON.stringify({label,clauses,A:C.A,caps:restored,D:D.toString('hex'),path:'claim/UTXO/window/vk'});
  ok(JSON.stringify(sim)===JSON.stringify(caps[i])&&simBase===base,'exact structured challenge to full view');
  ok(hash('CK',KB,simBase)===CK&&hash('Aux',KB,CK,simBase)===Aux,'full correlated CK/Aux simulator');fullViewCouplings++;
  for(const w of valid){const r=vector(C,w,false),decoded=recover(C,caps,r,q,delta);
   const k=Math.floor(decoded/65536),kb=decoded%65536;
   ok(k===K&&kb===KB,'valid witness same bound keys');ok(hash('CK',kb,base)===CK&&hash('Aux',kb,CK,base)===Aux,'joint CK Aux');
   ok(D.every((v,j)=>(v^pad(k,48)[j])===sigma[j]),'same capability');validOpens++;
  }
  if(h!==null){const decoded=recover(C,caps,h,q,delta),k=Math.floor(decoded/65536),kb=decoded%65536;
   ok(k===K&&kb===KB,'public FALSE unauthorized key recovery');
   ok(hash('CK',kb,base)===CK&&hash('Aux',kb,CK,base)===Aux,'FALSE checking key/aux bypass');
   ok(D.every((v,j)=>(v^pad(k,48)[j])===sigma[j]),'FALSE entire native capability bypass');falseBypasses++;
  }
 }
 return {label,variables:nvar,clauses:clauses.length,original_witnesses:valid.length,short_binary_kernel_representations:countShort,original_openings:validOpens,unauthorized_false_recoveries:falseBypasses,full_view_structured_challenge_couplings:fullViewCouplings,N:C.N,m:C.m,n:C.n,q,delta,false_near_short_l1:h===null?null:l1(h),false_structured_LWE_distinguisher_advantage_lower_bound:h===null?null:1-(2*l1(h)+1)/q};
}
const result={run:RUN,cases:[
 runCase('TRUE-original',2,[[1,2],[-1,2]],32),
 runCase('FALSE-original',1,[[1],[-1]],32),
 runCase('FALSE-with-eight-tautologies',1,[[1],[-1],...Array.from({length:8},()=>[1,-1])],8)
],assertions:0,quantum_security:'NOT_TESTED',general_source_security:'FALSE_BYPASS',qpt_original_reduction:'UNPROVED'};
result.assertions=checks;
console.log(JSON.stringify(result,null,2));
