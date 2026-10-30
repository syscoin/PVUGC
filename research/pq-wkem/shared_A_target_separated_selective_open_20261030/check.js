function check(){
  let tests=0; const ok=(v,m)=>{if(!v)throw Error(m);tests++};
  const q=5,m=3,T=[];
  for(let i=0;i<m;i++)for(const s of [-1,1]){const z=[0,0,0];z[i]=s;T.push(z)}
  let tv=0,tv2=0,X=0,X2=0,absent=0;
  for(let a=0;a<q;a++)for(let b=0;b<q;b++)for(let c=0;c<q;c++){
    const A=[a,b,c],f=Array(q).fill(0);
    for(const z of T){const u=(A.reduce((v,x,i)=>v+x*z[i],0)%q+q)%q;f[u]++}
    const p=f.map(n=>n/T.length);
    const t=p.reduce((v,x)=>v+Math.abs(x-1/q),0)/2;
    let t2=0;for(let u=0;u<q;u++)for(let v=0;v<q;v++)t2+=Math.abs(p[u]*p[v]-1/(q*q))/2;
    ok(t2<=2*t+1e-10,"same-A planted-column product TV");
    tv+=t;tv2+=t2;
    for(const n of f){X+=n;X2+=n*n;if(n===0)absent++}
  }
  tv/=q**m;tv2/=q**m;X/=q**(m+1);X2/=q**(m+1);
  ok(Math.abs(X-6/5)<1e-10,"source count first moment");
  ok(Math.abs(X2-X*X-24/25)<1e-10,"source count variance");
  ok(tv<=Math.sqrt((q-1)/T.length)/2+1e-10,"leftover hashing bound");
  ok(tv2<=2*tv+1e-10,"two planted targets bound");
  const Q=101,A=[[1,1,3,7],[2,2,4,8]],z1=[1,0,0,0],z2=[0,1,0,0],r=[9,11],noise=[1,-1,0,1],err=1,g=50;
  const U=[A[0][0],A[1][0]];
  const base=A[0].map((v,i)=>(v*r[0]+A[1][i]*r[1]+noise[i])%Q);
  for(const bit of [0,1]){
    const d=(U[0]*r[0]+U[1]*r[1]+err+g*bit)%Q;
    for(const z of [z1,z2]){
      const t=(d-z.reduce((v,x,i)=>v+x*base[i],0)%Q+Q)%Q;
      const distances=[0,g].map(v=>Math.min((t-v+Q)%Q,(v-t+Q)%Q));
      ok(distances[bit]<g/2 && distances[bit]<distances[1-bit],"different short openings same precommitted bit");
    }
  }
  const aBytes=256*6800*3,uBytes=256*52*3,ctBytes=(6800+52)*3;
  const naive=4*100*(aBytes+uBytes),shared=4*(aBytes+100*uBytes);
  ok(shared<naive,"storage improves without reusing targets");
  return {record:"shared_A_target_separated_selective_open_20261030",assertions:tests,finite:{mean_TV:tv,two_target_TV:tv2,source_mean:X,source_variance:X2-X*X,no_preimage:absent/q**(m+1)},storage_bytes:{naive,shared,aBytes,uBytes,ctBytes,savings_pct:100*(1-shared/naive)},scope_warning:"Same U reused across claims means any released short opening decrypts both, regardless of separate keys."};
}
console.log(JSON.stringify(check(), null, 2));
