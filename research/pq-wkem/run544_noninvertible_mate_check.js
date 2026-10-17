function run544(){
  const mask=(1n<<64n)-1n;
  const mix=(v)=>{v=(v+0x9e3779b97f4a7c15n)&mask;v=((v^(v>>30n))*0xbf58476d1ce4e5b9n)&mask;v=((v^(v>>27n))*0x94d049bb133111ebn)&mask;return(v^(v>>31n))&mask};
  const cases=[];let markedTotal=0,trivialTotal=0,hashTargets=0;
  for(let k=4;k<=7;k++)for(let j=0;j<4;j++){
    const N=1<<k,L=N<<3,ctx=(k<<12)+(j<<4),key=1+Number(mix(BigInt(ctx+123))%BigInt(N-1));
    const t=s=>Number(mix(BigInt(ctx*65536+s+819))%BigInt(N));
    const h=u=>mix(BigInt(ctx*65536+u+65521));
    const f=u=>h(u)^h(u^key);
    const cos=new Map();
    for(let u=0;u<N;u++){const v=f(u).toString();if(cos.has(v)){if((cos.get(v)^u)!==key)throw Error("cross coset collision");}else cos.set(v,u);}
    if(cos.size!==N/2)throw Error("fiber");
    const q=Math.max(2,Math.round(N**(1/3))),sample=new Map(),taken=new Set();let early=0;
    for(let z=0;z<L&&sample.size<q;z++){
      const s=(z*5+j+3)%L,u=t(s),v=f(u).toString();
      if(sample.has(v)){if(sample.get(v)!==u){if((sample.get(v)^u)!==key)throw Error("early");early++;}continue;}
      sample.set(v,u);taken.add(s);
    }
    if(sample.size!==q)throw Error("sample");
    let marked=0,trivial=0;
    for(let s=0;s<L;s++){if(taken.has(s))continue;const u=t(s),v=f(u).toString();if(sample.has(v)){if(u===sample.get(v))trivial++;else{marked++;if((u^sample.get(v))!==key)throw Error("mate");}}}
    if(marked===0||trivial===0)throw Error("coverage");
    const rho=marked/(L-q),theta=Math.asin(Math.sqrt(rho)),rounds=Math.max(0,Math.round(Math.PI/(4*theta)-.5)),p=Math.sin((2*rounds+1)*theta)**2;
    if(p<.85)throw Error("amplitude");
    for(const s of [0,L>>1,L-1]){const u=t(s),target=f(u)^h(u);if(target!==h(u^key))throw Error("target");hashTargets++;}
    cases.push({k,j,key,q,marked,trivial,early,rounds,grover_p:Number(p.toFixed(6))});markedTotal+=marked;trivialTotal+=trivial;
  }
  return {run:544,model:"Toy SplitMix64 public H,T; exact finite enumeration; not quantum execution",cases:cases.length,markedTotal,trivialTotal,hashTargets,passed:true,details:cases};
}
console.log(JSON.stringify(run544(),null,2));
