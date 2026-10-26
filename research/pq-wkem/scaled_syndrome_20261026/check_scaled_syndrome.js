const report=(function runScaledChecker(){
  let a=0;const ck=(x,s)=>{if(!x)throw Error(s);a++},mod=(x,q)=>(x%q+q)%q;
  for(const q of [4,8])for(let A0=0;A0<q;A0++)for(let A1=0;A1<q;A1++)
  for(let t=0;t<q;t++)for(let u=0;u<q;u++)for(let e=-1;e<=1;e++){
    const s0=mod(t-u,q),s1=u;
    ck(mod(A0*s0+A1*s1+e,q)===mod(A0*t+(A1-A0)*u+e,q),"nonprimitive b joint embedding");
    ck(mod((q/2)*(s0+s1),q)===mod((q/2)*t,q),"secret projection");
  }
  for(const q of [4,8])for(let t=0;t<q;t++){
    const h=new Map;
    for(let u=0;u<q;u++)for(let e=-1;e<=1;e++){
      const p=mod(2*t+u+e,q);h.set(p,(h.get(p)||0)+1);
    }
    ck(h.size===q&&[...h.values()].every(x=>x===3),"false full-rank conditional uniformity");
  }
  const q=32,g=16;let ws=[];
  for(let mask=0;mask<16;mask++)if((((mask&1)+((mask>>1)&1))&1)===1)ws.push(mask);
  ck(ws.length===8,"multiple valid witnesses");
  const dist=(x,p)=>Math.min(mod(x-p,q),mod(p-x,q));
  let recovered=0;
  for(let t0=0;t0<4;t0++)for(let t1=0;t1<4;t1++)for(let K=0;K<4;K++){
    const pad=(t0&1)|((t1&1)<<1),D=K^pad;
    for(let j=0;j<2;j++)for(const w of ws)
    for(let x0=-1;x0<=1;x0++)for(let x1=-1;x1<=1;x1++)
    for(let x2=-1;x2<=1;x2++)for(let x3=-1;x3<=1;x3++){
      const t=j?t1:t0,errors=[x0,x1,x2,x3];
      const p=errors.map((e,i)=>mod((i<2?g:0)*t+e,q));
      const y=p.reduce((s,z,i)=>s+(((w>>i)&1)*z),0)%q;
      const P=dist(y,0)<dist(y,g)?0:g;
      ck(P===g*(t&1),"all-original-witness exact rounding");
      const z0=j?(t0&1):(P/g),z1=j?(P/g):(t1&1);
      ck((D^(z0|(z1<<1)))===K,"identical precommitted key");
      recovered++;
    }
  }
  let re=new Map,ideal=new Map;
  const idx=(K,p0,p1,D)=>`${K}:${K&1}:${p0}:${p1}:${D}`;
  for(let K=0;K<4;K++)for(let t0=0;t0<4;t0++)for(let t1=0;t1<4;t1++)
  for(let p0=0;p0<4;p0++)for(let p1=0;p1<4;p1++){
    const h=idx(K,p0,p1,K^((t0&1)|((t1&1)<<1)));
    re.set(h,(re.get(h)||0)+1);
  }
  for(let K=0;K<4;K++)for(let p0=0;p0<4;p0++)for(let p1=0;p1<4;p1++)
  for(let D=0;D<4;D++)ideal.set(idx(K,p0,p1,D),4);
  ck(re.size===ideal.size&&[...re].every(([h,n])=>ideal.get(h)===n),"whole uniform-column pk-correlated null law");
  return {status:"PASS",assertions:a,release_opens_rechecked:recovered,noise_bound:1,nonprimitive_helper_bits:0,scope:"finite exact equalities only; not a QPT-LWE hardness or native signature test"};
})();
console.log(JSON.stringify(report,null,2));
