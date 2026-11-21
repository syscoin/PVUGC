function checker(){
const q=65537,g=8192;let state=20261031,count=0;
const r=n=>(state=(Math.imul(state,1664525)+1013904223)>>>0)%n;
const md=n=>((n%q)+q)%q;
const dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
const ck=(v,msg)=>{count++;if(!v)throw Error(msg)};
let pair=0;
for(let trial=0;trial<128;trial++){
 const u=[r(q),r(q)],R=Array.from({length:2},()=>Array.from({length:3},()=>r(q)));
 const B=R.map((row,i)=>[md(u[i]+row[0]),row[1],row[2]]);
 const s=[r(q),r(q)],noise=[r(3)-1,r(3)-1,r(3)-1],star=r(3)-1;
 const K=[r(2),r(2),r(2)];
 for(let j=0;j<3;j++){
  const S=[r(q),r(q),r(q)],k=K[j];
  const P=[md(k+S[0]),S[1],S[2]];
  const c=P.map((p,i)=>md(dot(s,B.map(row=>row[i]))+g*p+noise[i]));
  const t=md(dot(u,s)+star);
  const H=S.map((v,a)=>md(dot(s,R.map(row=>row[a]))+g*v));
  const cf=[md(t+g*k+H[0]+noise[0]-star),md(H[1]+noise[1]),md(H[2]+noise[2])];
  ck(cf.every((v,i)=>v===c[i]),"full factorization of correlated view");
  const Snew=[md(S[0]+2*k-1),S[1],S[2]];
  const Pnew=[md((1-k)+Snew[0]),Snew[1],Snew[2]];
  ck(Pnew.every((v,i)=>v===P[i]),"bit flip with leakage preserving translation");
  ck(Snew[1]===S[1]&&Snew[2]===S[2],"safe disclosed mask coordinates");
  ck(md(P[0]-S[0])===k,"complete unsafe mask disclosure reveals key");
  const Hfree=[md(H[0]+g*k),H[1],H[2]];
  const cfree=[md(t+Hfree[0]+noise[0]-star),md(Hfree[1]+noise[1]),md(Hfree[2]+noise[2])];
  ck(cfree.every((v,i)=>v===c[i]),"K-free shift simulator exact");
  pair++;
 }
}
const distributions=[];
for(let k0=0;k0<2;k0++)for(let k1=0;k1<2;k1++){
 const d=new Map;
 for(let s0=0;s0<5;s0++)for(let s1=0;s1<5;s1++){
  const key=[(2*(s0+k0))%5,(2*(s1+k1))%5].join(",");
  d.set(key,(d.get(key)||0)+1)
 }
 distributions.push(JSON.stringify([...d].sort()))
}
ck(distributions.every(x=>x===distributions[0]),"independent masks give joint K-independent view");
const a=new Set(Array.from({length:5},(_,s)=>[2*s%5,2*s%5].join(",")));
const b=new Set(Array.from({length:5},(_,s)=>[2*s%5,(2*(s+1))%5].join(",")));
ck([...a].every(x=>!b.has(x)),"reuse leaks key difference");
return {checks:count,related_capsule_couplings:pair,small_field_full_distribution_states:25,coin_exposed_leak_condition_verified:true,mask_reuse_failure_verified:true,complete_generic_WKEM:false};
}
console.log(JSON.stringify(checker(),null,2));
