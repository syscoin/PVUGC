// Exact executed R76 V8 function, standard JavaScript; deterministic
const check = (function r76Checker() {
  let assertions=0;
  const check=(v,name)=>{assertions++;if(!v)throw Error("ASSERT "+assertions+" "+name);};
  const dot=(r,v,q)=>r.reduce((a,x,i)=>a+x*v[i],0)%q;
  const norm=(x,q)=>(x%q+q)%q;
  const r1=[1,1,0],r2=[1,0,1],A=[4,-4,-4],g=4,q=32,p=8,Delta=8,e0=[1,0,0];
  const good=A.map(a=>norm(3*a,q)),bad=[0,4,0];
  const make=(z,u,mu,B)=>A.map((a,i)=>{
    const v=norm(a*z+B[i]*u+Delta*mu*e0[i],q);
    check(v%g===0,"rounding grid");
    return v/g;
  });
  const hist=(items)=>{const h=new Map();for(const v of items){const k=v.join(",");h.set(k,(h.get(k)||0)+1)}return h};
  check(norm(dot(r1,A,q),q)===0&&norm(dot(r2,A,q),q)===0,"source kernels");
  check(dot(r1,e0,q)===1&&dot(r2,e0,q)===1,"normalization");
  const results=[];
  for(let mu=0;mu<2;mu++){
    const base=[],masked=[];
    for(let z=0;z<q;z++){
      base.push(make(z,0,mu,[0,0,0]));
      for(let u=0;u<q;u++){
        const v=make(z,u,mu,good);masked.push(v);
        check(norm(dot(r1,v,p),p)===2*mu,"first ORIGINAL witness");
        check(norm(dot(r2,v,p),p)===2*mu,"second ORIGINAL witness");
      }
    }
    const hb=hist(base), hm=hist(masked);
    check(hb.size===hm.size,"same support");
    for(const [k,v] of hb)check(hm.get(k)===v*q,"same distribution");
    let success1=0,success2=0;
    for(let z=0;z<q;z++)for(let u=0;u<q;u++){
      const v=make(z,u,mu,bad);
      success1+=Number(norm(dot(r1,v,p),p)===2*mu);
      success2+=Number(norm(dot(r2,v,p),p)===2*mu);
    }
    check(success1===q*q/p,"bad mask first witness 1/p");
    check(success2===q*q,"bad mask second witness okay");
    results.push({mu,badSuccessR1:success1,badSuccessR2:success2,total:q*q});
  }
  let compatible=0;const im=new Set();
  for(let t=0;t<q;t++)im.add(A.map(a=>norm(a*t,q)).join(","));
  for(let a=0;a<p;a++)for(let b=0;b<p;b++)for(let c=0;c<p;c++){
    const B=[a*g,b*g,c*g];
    const okay=norm(dot(r1,B,q),q)===0 && norm(dot(r2,B,q),q)===0;
    if(okay){compatible++;check(im.has(B.join(",")),"compatible implies image");}
    if(im.has(B.join(",")))check(okay,"image implies compatible");
  }
  check(compatible===p&&im.size===p,"annihilator=image in toy");
  const Q=17,Af=[1,-1,-1],Bg=[5,-5,-5],Bb=[0,1,0];
  const field=(z,u,mu,B)=>Af.map((a,i)=>norm(a*z+B[i]*u+mu*e0[i],Q));
  for(let mu=0;mu<2;mu++){
    const base=[],masked=[];
    for(let z=0;z<Q;z++){
      base.push(field(z,0,mu,[0,0,0]));
      for(let u=0;u<Q;u++)masked.push(field(z,u,mu,Bg));
    }
    const hb=hist(base),hm=hist(masked);
    check(hb.size===hm.size,"field exact support");
    for(const [k,v] of hb)check(hm.get(k)===v*Q,"field exact distribution");
    let goodOpen=0;
    for(let z=0;z<Q;z++)for(let u=0;u<Q;u++)
      goodOpen+=Number(norm(dot(r1,field(z,u,mu,Bb),Q),Q)===mu);
    check(goodOpen===Q,"field bad mask 1/q");
  }
  return {run:"R76-WITNESS-ANNIHILATOR-20261104",status:"NO_POSITIVE_WKEM_ADVANCE",
    executedLanguage:"JavaScript V8",assertions,rounded:{q:32,p:8,maskColumnsExamined:512,
      compatibleColumns:compatible,compatibleEqualsSourceImage:true,results},
    field:{q:17,badMaskFirstWitnessSuccess:"1/17"},
    scope:"Exact finite sources; no QPT, generic NP, security or key-recovery extraction claim"};
});
console.log(JSON.stringify(check(),null,2));
