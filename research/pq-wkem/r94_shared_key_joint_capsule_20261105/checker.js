function R94_checker(){
  const p=5;let assertions=0;
  const count={shamir_fixed_U_privacy:0,authorized_reconstruction:0,shared_key_tv:0,public_key_resource:0};
  function ok(x,msg){assertions++;if(!x)throw Error("Assertion "+assertions+": "+msg)}
  const mod=x=>((x%p)+p)%p;
  const inv=x=>{for(let z=1;z<p;z++)if(mod(x*z)===1)return z;throw Error("no inverse")};
  function subsets(n){let out=[];for(let z=0;z<(1<<n);z++){let xs=[];for(let i=0;i<n;i++)if(z&(1<<i))xs.push(i);out.push(xs)}return out}
  const sets=subsets(4);
  const memo=new Map();
  for(let root=0;root<p;root++)for(let a=0;a<p;a++)for(let b=0;b<p;b++){
    const vals=[1,2,3,4].map(x=>mod(root+a*x+b*x*x));
    for(const U of sets){
      if(U.length>=3){
        let re=0;
        for(const i of U.slice(0,3)){
          let factor=1;
          for(const j of U.slice(0,3))if(j!==i)factor=mod(factor*(j+1)*inv(mod(j-i)));
          re=mod(re+vals[i]*factor);
        }
        ok(re===root,"authorized interpolation");
        count.authorized_reconstruction++;
      }else{
        const k=root+":"+U.join(",");
        if(!memo.has(k))memo.set(k,new Map());
        const seq=U.map(i=>vals[i]).join(",");
        const d=memo.get(k);d.set(seq,(d.get(seq)||0)+1);
      }
    }
  }
  for(const U of sets.filter(x=>x.length<3)){
    const ref=memo.get("0:"+U.join(","));
    for(let root=1;root<p;root++){
      const got=memo.get(root+":"+U.join(","));
      ok(ref.size===got.size && [...ref].every(([k,v])=>got.get(k)===v),"exact joint privacy for one public global set of keys");
      count.shamir_fixed_U_privacy++;
    }
  }
  const rs=[];
  for(let a=-1;a<=1;a++)for(let b=-1;b<=1;b++)for(let c=-1;c<=1;c++)rs.push([a,b,c]);
  let total1=0,total2=0;
  for(let a=0;a<p;a++)for(let b=0;b<p;b++)for(let c=0;c<p;c++){
    const hist=Array(p).fill(0);
    for(const r of rs)hist[mod(a*r[0]+b*r[1]+c*r[2])]++;
    const probs=hist.map(n=>n/rs.length);
    const d1=probs.reduce((t,v)=>t+Math.abs(v-1/p),0)/2;
    let d2=0;
    for(const x of probs)for(const y of probs)d2+=Math.abs(x*y-1/(p*p));
    d2/=2;
    ok(d2<=2*d1+1e-12,"shared public key with fresh randomness product TV bound");
    total1+=d1;total2+=d2;count.shared_key_tv++;
  }
  ok(total2<=2*total1+1e-12,"average strong-error composition");
  const n=16,caps=16,m=1649,d=256,ell=16;
  const saved=(caps-1)*n*m*(d+ell);
  ok(saved===107646720,"shared public LWE matrix savings");
  count.public_key_resource++;
  return {run:"R94-SHARED-KEY-JOINT-CAPSULE-20261105",assertions,count,
    avg_single_tv:total1/125,avg_two_tv:total2/125,
    saved_mod_q_elements:saved,saved_bytes_at_q_lt_65536:2*saved,
    scope:"GF5 and fixed-key product census only; NOT LWE/PQ security"};
}
console.log(JSON.stringify(R94_checker(), null, 2));
