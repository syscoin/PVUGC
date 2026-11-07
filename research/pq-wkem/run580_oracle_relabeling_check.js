function run580Checker(){
 let count=0,views=0,equalities=0,affine=0,periods=0;
 const ck=(v,m)=>{count++;if(!v)throw Error(m)};
 function perms(n){const out=[],a=Array.from({length:n},(_,i)=>i);function rec(i){if(i===n){out.push([...a]);return}for(let j=i;j<n;j++){[a[i],a[j]]=[a[j],a[i]];rec(i+1);[a[i],a[j]]=[a[j],a[i]]}}rec(0);return out}
 const N=4,ps=perms(N);
 for(const B of ps)for(let d1=0;d1<N;d1++)for(let d2=0;d2<N;d2++){
  const seen=new Set();
  for(const p1 of ps)for(const p2 of ps){
   const f1=Array.from({length:N},(_,x)=>p1[B[x^d1]]);
   const f2=Array.from({length:N},(_,x)=>p2[B[x^d2]]);
   const key=f1.join(",")+"|"+f2.join(",");
   ck(!seen.has(key),"distribution not independent");
   seen.add(key);views++;
  }
  ck(seen.size===ps.length**2,"distribution not uniform");
  const h=d1^d2;
  for(let s=0;s<N;s++)for(let t=0;t<N;t++){
   ck((B[s^d1]===B[t^d2])===((s^t)===h),"not a point function");
   equalities++;
  }
 }
 for(let n=2;n<=5;n++){
  const size=2**n,mask=size-1;
  const m1=x=>x^((x<<1)&mask);
  const m2=x=>x^(x>>1);
  const inv2=Array(size);
  for(let j=0;j<size;j++)inv2[m2(j)]=j;
  for(const M of [m1,m2]){
   for(let d=0;d<size;d++){
    const intercepts=new Set();
    for(let r=0;r<size;r++){
     const b=M(d)^r;intercepts.add(b);
     for(let s=0;s<size;s++){ck((M(s^d)^r)===(M(s)^b),"affine map");affine++}
    }
    ck(intercepts.size===size,"affine shift leaked");
   }
  }
  for(let d1=0;d1<size;d1++)for(let d2=0;d2<size;d2++){
   const r1=3%size,r2=1;
   const g1_0=m1(d1)^r1, g2_0=m2(d2)^r2;
   const aligned=m2(d1)^r2; // public T(g1_0)
   const h=inv2[aligned^g2_0];
   ck(h===(d1^d2),"affine translator did not reveal shift");
   periods++;
  }
 }
 const theta=Math.asin(1/16),rounds=Math.round(Math.PI/(4*theta)-.5);
 const success=Math.sin((2*rounds+1)*theta)**2;
 ck(success>.99,"quantum Grover rotation");
 return {run:580,result:"PASS",assertions:count,exhaustive_relabeling_views:views,latent_equality_checks:equalities,affine_transparent_checks:affine,affine_translator_recoveries:periods,grover_n8_rounds:rounds,grover_n8_success:Number(success.toFixed(12)),scope:"Finite identities and known search formula; not a practical WKEM or quantum implementation"};
}
console.log(JSON.stringify(run580Checker(),null,2));
