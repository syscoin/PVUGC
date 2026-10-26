// Bounded exact arithmetic checks; not LWE/native security tests. Node >=18.
let assertions=0; const test=(v,m)=>{if(!v)throw Error(m);assertions++};
const qdot=(a,b,q)=>a.reduce((z,x,i)=>z+x*b[i],0)%q;
const vecs=(base,n)=>n===0?[[]]:vecs(base,n-1).flatMap(v=>Array.from({length:base},(_,j)=>[...v,j]));
const prod=(a,w,q)=>a.map(row=>qdot(row,w,q));
const binary=n=>vecs(2,n);
let exactEnsembles=[];
for(const [q,m,n] of [[2,2,5],[4,2,2]]){
 const b=[1,...Array(m-1).fill(0)], W=binary(n).filter(w=>w.some(Boolean));
 let s=0,s2=0,zeros=0,total=0;
 for(const flat of vecs(q,m*n)){
  const A=Array.from({length:m},(_,i)=>flat.slice(i*n,(i+1)*n));
  const N=W.reduce((t,w)=>t+Number(prod(A,w,q).every((v,i)=>v===b[i])),0);
  s+=N;s2+=N*N; zeros+=Number(N===0);total++;
 }
 const mu=W.length/q**m,variance=mu*(1-q**(-m));
 test(Math.abs(s/total-mu)<1e-12,'mean');
 test(Math.abs(s2/total-mu*mu-variance)<1e-12,'variance');
 test(zeros/total<=Math.min(1,1/mu),'false fraction');
 exactEnsembles.push({q,m,n,false_count:zeros,total});
}
for(const w of binary(5).filter(v=>v.some(Boolean)))
 for(const v of binary(5).filter(x=>x.some(Boolean)&&x.join('')>w.join('')))
  test(w.some((x,i)=>v.some((y,j)=>i!==j&&Math.abs(x*y-w[j]*v[i])===1)),'unit minor');
const q=4,A=[[2,3],[1,0],[0,1],[1,1]],b=[1,0,0,0];
test(vecs(q,2).every(w=>prod(A,w,q).some((x,i)=>x!==b[i])),'no modular witness');
const law=new Map;
for(const s of vecs(q,4))for(const e of vecs(3,2)){
 const P=s[0],p=[0,1].map(j=>(A.reduce((v,row,i)=>v+row[j]*s[i],0)+e[j]-1+100*q)%q);
 const key=`${P}:${p.join(',')}`;law.set(key,(law.get(key)||0)+1);
}
for(let P=0;P<q;P++)for(const p of vecs(q,2))test(law.get(`${P}:${p.join(',')}`)===36,'full false P/p law');
const Q=32,DELTA=16,BETA=1;
const At=[[7,13,26,20],[3,5,29,27],[11,8,21,24]], bt=[1,0,0];
const Ws=binary(4).filter(w=>prod(At,w,Q).every((v,i)=>v===bt[i]));
test(Ws.length>=2,'distinct true witnesses');
let state=20261026>>>0;const rand=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state};
for(let trial=0;trial<60;trial++){
 let P=[],p=[],h=[];for(let j=0;j<8;j++){
  const s=Array.from({length:3},()=>rand()%Q),e=Array.from({length:4},()=>rand()%3-1);
  P.push(s[0]);h.push(s[0]%DELTA);
  p.push(Array.from({length:4},(_,i)=>(At.reduce((t,row,z)=>t+row[i]*s[z],e[i])+100*Q)%Q));
 }
 const K=rand()%256,pad=P.reduce((z,x,j)=>z+(((x-h[j])/DELTA)<<j),0),D=K^pad;
 for(const w of Ws){let recovery=[];
  for(let j=0;j<8;j++){
   const t=qdot(w,p[j],Q),choices=[h[j],h[j]+DELTA];
   const ds=choices.map(x=>Math.min((t-x+Q)%Q,(x-t+Q)%Q));
   test(ds[0]!==ds[1],'unique rounding');recovery.push(choices[ds[0]<ds[1]?0:1]);
  }
  test(recovery.every((x,j)=>x===P[j]),'all witness P recovery');
  test((D^recovery.reduce((z,x,j)=>z+(((x-h[j])/DELTA)<<j),0))===K,'same K');
 }
}
const report={status:'PASS',assertions,ensembles:exactEnsembles,false_law_P_p:law.size,true_witnesses:Ws.length,true_setups:60,scope:'finite exact arithmetic only; NO hardness/security parameter claim'};
console.log(JSON.stringify(report,null,2));
