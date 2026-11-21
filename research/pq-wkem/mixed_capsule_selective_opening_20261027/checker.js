const result = (function offlineChecker(){
 let checks=0; const ok=(b,m)=>{if(!b)throw Error(m);checks++};
 const q=7,noise=[-1,0,1],P=[new Map(),new Map()];
 const add=(m,k,v)=>m.set(k,(m.get(k)||0)+v);
 for(let t=0;t<2;t++)for(let u=0;u<q;u++)for(const a of noise)for(const b of noise)
   add(P[t],((u+a+t)%q+q)%q+","+((u+b)%q+q)%q,1);
 const diff=(a,b)=>{let s=0;for(const k of new Set([...a.keys(),...b.keys()]))s+=Math.abs((a.get(k)||0)-(b.get(k)||0));return s};
 const single=diff(P[0],P[1]);
 ok(single===42,"nontrivial source digit TV=42/126");
 let joint=[];
 for(let K=0;K<4;K++){
   const pk=(K*K+1)%3, real=new Map(),nil=new Map();
   for(let U=0;U<4;U++)for(let Z=0;Z<4;Z++){
     const D=U^Z,V=K^U;
     for(const [p,count] of P[Z&1])add(real,[pk,D,V,p].join(":"),count);
   }
   for(let D=0;D<4;D++)for(let V=0;V<4;V++)
     for(const [p,count] of P[0])add(nil,[pk,D,V,p].join(":"),count);
   const total=m=>[...m.values()].reduce((a,b)=>a+b,0);
   ok(total(real)===1008&&total(nil)===1008,"total full-public probability");
   const n=diff(real,nil);ok(n===336,"full conditional TV=336/2016=1/6");
   const opening=[["other:K0:U0:Z0",2],["other:K1:U1:Z1",1],["other:K2:U3:Z1",4]];
   const tensor=m=>{let out=new Map();for(const [t,v] of m)for(const [o,w] of opening)add(out,t+"|"+o,v*w);return out};
   ok(diff(tensor(real),tensor(nil))===7*n,"arbitrary independent selected-open records tensor exactly");
   let pairs=new Set();
   for(let U=0;U<4;U++)for(let Z=0;Z<4;Z++){
     const D=U^Z,V=K^U;
     pairs.add(D+":"+V);
     ok((V^U)===K,"opening any target-seed-sharing pad reveals K");
   }
   ok(pairs.size===16,"target public pair uniform for fixed K");
   joint.push({K,pk_surrogate:pk,TV_num:n,TV_den:2016});
 }
 return {record:"mixed_capsule_selective_opening_20261027",toy_q:q,source_M:[1,1],source_e:[1,0],radix_digits:[0,1],single_column_TV:"42/126 = 1/3",full_conditional_joint_TV:"336/2016 = 1/6",opened_independent_other_capsule_tensor_identity:true,shared_key_opening_exposes_target_key:true,keys:joint,assertions:checks,scope:"Exact finite algebra only; full cubic certificate and 37-column mixed-capsule test independently executed in local Python archive; no QPT hardness test"};
})();
console.log(JSON.stringify(result,null,2));
