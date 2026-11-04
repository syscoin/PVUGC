function checkR58() {
  "use strict";
  const q=(1n<<272n)-237n, D=65536n, L=1n<<256n, N=64;
  const clauses=[
    [[1,3,4],[0,0,0]],[[0,1,4],[0,0,0]],[[0,1,4],[1,0,1]],[[1,3,5],[1,0,1]],
    [[1,3,4],[1,0,0]],[[0,1,2],[0,0,0]],[[0,3,4],[0,1,1]],[[2,3,5],[1,0,0]],
    [[0,4,5],[1,1,0]],[[1,2,5],[1,1,1]],[[1,2,4],[1,0,0]],[[0,3,4],[1,0,0]],
    [[0,4,5],[0,0,1]],[[2,4,5],[1,0,0]],[[2,3,4],[0,1,1]],[[0,3,5],[0,0,1]],
    [[0,4,5],[0,1,0]],[[1,3,4],[0,1,0]],[[1,2,4],[1,1,0]]
  ];
  let checks=0;
  const ck=(b,m)=>{checks++;if(!b)throw Error(m);};
  const mod=x=>((x%q)+q)%q;
  const zero=()=>Array(N).fill(0n);
  const one=()=>{const a=zero();a[0]=1n;return a;};
  const mul=(a,b)=>{
    const c=zero();
    for(let i=0;i<N;i++)if(a[i])for(let j=0;j<N;j++)if(b[j])c[i|j]=mod(c[i|j]+a[i]*b[j]);
    return c;
  };
  const fail=([vars,bits])=>{
    let a=one();
    for(let k=0;k<vars.length;k++){
      const v=zero();
      if(bits[k])v[1<<vars[k]]=1n;
      else {v[0]=1n;v[1<<vars[k]]=q-1n;}
      a=mul(a,v);
    }
    return a;
  };
  const fs=clauses.filter((_,i)=>i!==10).map(fail),gen=[];
  for(let i=0;i<fs.length;i++)for(let j=i;j<fs.length;j++)gen.push(mul(fs[i],fs[j]));
  for(let s=0;s<N;s++)if(s.toString(2).split("1").length-1<=2){
    const z=zero();z[s]=1n;
    for(const f of fs)gen.push(mul(f,z));
  }
  const piv=new Map();
  for(const g of gen){
    let t=g.slice();
    for(let i=0;i<N;i++){
      if(!t[i])continue;
      if(!piv.has(i)){
        let base=t[i],power=q-2n,inv=1n;
        while(power){if(power&1n)inv=mod(inv*base);base=mod(base*base);power>>=1n;}
        piv.set(i,t.map(x=>mod(x*inv)));break;
      }
      const co=t[i],p=piv.get(i);
      t=t.map((x,j)=>mod(x-co*p[j]));
    }
  }
  const inds=[...piv.keys()].sort((a,b)=>a-b);
  const free=Array.from({length:N},(_,i)=>i).filter(i=>!piv.has(i));
  const P=a=>{
    let t=a.map(mod);
    for(const i of inds)if(t[i]){const co=t[i],p=piv.get(i);t=t.map((x,j)=>mod(x-co*p[j]));}
    return free.map(i=>t[i]);
  };
  const S=z=>{const t=zero();free.forEach((i,j)=>t[i]=z[j]);return t;};
  const eq=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
  ck(piv.size===61&&free.length===3,"true quotient dimension");
  for(const g of gen)for(let k=0;k<6;k++){
    const v=zero();v[1<<k]=1n;
    ck(P(mul(g,v)).every(x=>x===0n),"full ideal closure");
  }
  const E=free.map((_,i)=>free.map((_,j)=>BigInt(i===j)));
  const quotientMul=(x,y)=>P(mul(S(x),S(y)));
  const tb=E.map(e=>mod(E.reduce((a,u,i)=>a+quotientMul(e,u)[i],0n)));
  const trace=z=>mod(z.reduce((a,v,i)=>a+v*tb[i],0n));
  ck(eq(tb,[3n,2n,1n]),"computed public trace basis");
  ck(trace(P(one()))===3n,"trace of one");
  const ev=(a,w)=>mod(a.reduce((s,v,i)=>s+(((i&w)===i)?v:0n),0n));
  const witnesses=Array.from({length:N},(_,i)=>i).filter(w=>fs.every(f=>ev(f,w)===0n));
  ck(eq(witnesses,[10,11,43]),"fixture validation only");
  for(let j=0;j<32;j++){
    const a=Array.from({length:N},(_,i)=>BigInt((j*13+i*19)%15-7));
    ck(trace(P(a))===mod(witnesses.reduce((s,w)=>s+ev(a,w),0n)),"trace proof validation");
  }
  const c=BigInt(free.length),step=c*D,publicBound=c*BigInt(N);
  let minDist=q;
  for(let k=0n;k<=3n;k++){
    const d0=(k*q)/step;
    for(const d of [d0-1n,d0,d0+1n])if(d>=1n&&d<L){
      const v=step*d-k*q,dist=v<0n?-v:v;
      if(dist<minDist)minDist=dist;
    }
  }
  ck(minDist===65299n&&2n*publicBound<minDist,"global trace codeword separation");
  const decode=z=>{
    const t=trace(z), candidates=[];
    for(let k=-1n;k<=c;k++){
      const y=t+k*q,h=(y+step/2n)/step;
      for(const u of [h-1n,h,h+1n])if(u>=0n&&u<L){
        const err=y-step*u;
        if(err>=-publicBound&&err<=publicBound)candidates.push(u);
      }
    }
    const distinct=[...new Set(candidates.map(String))];
    ck(distinct.length===1,"unique public trace decoding");
    return BigInt(distinct[0]);
  };
  let seed=0x1234abcdeffedcba987654321n;
  const mask=(1n<<256n)-1n;
  const next=()=>{seed=(seed*6364136223846793005n+1442695040888963407n)&mask;return seed;};
  const words=Array.from({length:257},()=>next());
  words.splice(0,4,0n,1n,L-2n,L-1n);
  const recoveredWords=[];
  for(let i=0;i<257;i++){
    const mu=words[i],eta=Array.from({length:N},(_,j)=>BigInt((i*19+j*13)%3-1));
    const a=eta.slice();a[0]+=D*mu;
    const z=P(a);
    const recovered=decode(z);
    ck(recovered===mu,"secret word recovered with no witness");
    recoveredWords.push(recovered);
  }
  for(const mu of [0n,1n,L-2n,L-1n])for(const e of [-1n,1n]){
    const a=Array(N).fill(e);a[0]+=D*mu;
    ck(decode(P(a))===mu,"boundary word and extreme noise");
  }
  const cap=Array.from({length:8192},(_,i)=>(i*73+19)%256);
  const bytes=arr=>arr.slice(0,256).flatMap(w=>Array.from({length:32},(_,i)=>Number((w>>BigInt(8*(31-i)))&255n)));
  const originalPad=bytes(words),recoveredPad=bytes(recoveredWords);
  const masked=cap.map((v,i)=>v^originalPad[i]);
  const rebuilt=masked.map((v,i)=>v^recoveredPad[i]);
  ck(eq(cap,rebuilt)&&eq(originalPad,recoveredPad),"8192-byte signature recovered only from decoded capsule");
  ck(recoveredWords[256]===words[256],"secret correlated CK seed recovered");
  return {run:"R58-PUBLIC-QUOTIENT-TRACE-20261104",checks,rank:piv.size,quotient_dimension:free.length,public_trace_basis:tb.map(String),public_noise_bound:String(publicBound),minimum_trace_codeword_distance:String(minDist),recovered_words:recoveredWords.length,fixture_witnesses_validation_only:witnesses,full_capability_recovery_without_original_witness:true,hard_true_qpt_security:"UNPROVED",positive_construction_advance:false};
}
console.log(JSON.stringify(checkR58(),null,2));
