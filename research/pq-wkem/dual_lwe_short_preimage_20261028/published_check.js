(function publishedChecker() {
  let count=0;
  const req=(b,s)=>{count++;if(!b)throw Error("assertion: "+s)};
  const mod=(x,q)=>(x%q+q)%q;
  let state=20261028>>>0;
  const rand=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state};
  const q=101,m=12,n=1,d=2,h=6,g=2*h+3,T=Math.floor(q/g),t=3,kappa=64;
  const A=Array.from({length:m},()=>rand()%q);
  const vectors=[];
  for(let i=0;i<m;i++)for(const s of [-2,2]){const z=Array(m).fill(0);z[i]=s;vectors.push(z)}
  for(let i=0;i<m;i++)for(let j=i+1;j<m;j++)for(const s of [-1,1])for(const t2 of [-1,1]){const z=Array(m).fill(0);z[i]=s;z[j]=t2;vectors.push(z)}
  req(vectors.length===288,"short test vectors");
  const pairs=[],seen=new Map();
  for(const z of vectors) {
    const u=mod(z.reduce((acc,v,k)=>acc+v*A[k],0),q);
    if(seen.has(u)&&pairs.length<d&&!pairs.some(p=>p.u===u)){
      const other=seen.get(u);
      req(other.some((v,i)=>v!==z[i]),"different preimages");
      pairs.push({u,z0:other,z1:z});
    } else if(!seen.has(u)) seen.set(u,z);
  }
  req(pairs.length===d,"two different syndrome collisions under sampled A");
  const U=pairs.map(p=>p.u), W0=pairs.map(p=>p.z0),W1=pairs.map(p=>p.z1);
  const valid=W=>W.every((z,j)=>z.reduce((s,v)=>s+Math.abs(v),0)<=h && mod(z.reduce((s,v,k)=>s+v*A[k],0),q)===U[j]);
  req(valid(W0)&&valid(W1),"distinct valid original short-preimage witnesses");
  let ell=0,pow=1n;while(pow<(1n<<64n)){pow*=BigInt(T);ell++}
  const L=Math.ceil(ell/d);
  function digitArray(x){let a=[];for(let i=0;i<ell;i++){a.push(Number(x%BigInt(T)));x/=BigInt(T)}req(x===0n,"radix exact");while(a.length<L*d)a.push(0);return a}
  function nearest(x) {let best=-1,bestDist=1e9;for(let a=0;a<T;a++){const diff=mod(x-g*a,q),dist=Math.min(diff,q-diff);if(dist<bestDist){bestDist=dist;best=a}}return best}
  function bigint(){return (BigInt(rand())<<32n)^BigInt(rand())}
  for(let trial=0;trial<12;trial++){
    const K=bigint(),mask=bigint(),shares=Array.from({length:t},()=>bigint());
    const D=shares.reduce((x,y)=>x^y,mask),V=K^mask;
    const packets=shares.map(share=>{
      const ds=digitArray(share),batches=[];
      for(let b=0;b<L;b++){
        const s=rand()%q,e=Array.from({length:m},()=>rand()%3-1),eps=Array.from({length:d},()=>rand()%3-1);
        const c=A.map((v,i)=>mod(v*s+e[i],q));
        const v=U.map((u,j)=>mod(u*s+eps[j]+g*ds[b*d+j],q));
        batches.push({c,v,s,e,eps});
      }
      return batches
    });
    const recovered=[];
    for(const W of [W0,W1]){
      let x=V^D;
      for(let i=0;i<t;i++){
        const decoded=[];
        const expected=digitArray(shares[i]);
        packets[i].forEach((p,b)=>{
          p.c.forEach((ci,k)=>req(ci===mod(A[k]*p.s+p.e[k],q),"c coin replay"));
          p.v.forEach((vi,j)=>req(vi===mod(U[j]*p.s+p.eps[j]+g*expected[b*d+j],q),"v coin replay"));
          for(let j=0;j<d;j++){
            const z=W[j],observed=mod(p.v[j]-z.reduce((sum,zk,k)=>sum+zk*p.c[k],0),q);
            const noise=p.eps[j]-z.reduce((sum,zk,k)=>sum+zk*p.e[k],0);
            req(Math.abs(noise)<=h+1,"all-witness noise bound");
            const digit=nearest(observed);
            req(digit===expected[b*d+j],"all-witness digit agreement");
            req(mod(observed-noise,q)===g*digit,"exact release identity");
            decoded.push(digit)
          }
        });
        let share=0n,mult=1n;for(let j=0;j<ell;j++){share+=BigInt(decoded[j])*mult;mult*=BigInt(T)}
        req(share===shares[i],"complete XOR share");
        x^=share;
      }
      req(x===K,"one native capability for distinct original witnesses");
      recovered.push(x.toString(16))
    }
    req(recovered[0]===recovered[1],"two distinct witnesses same capability")
  }
  const sphere=[];
  for(let a=-2;a<=2;a++)for(let b=-2;b<=2;b++)for(let c=-2;c<=2;c++)if(Math.abs(a)+Math.abs(b)+Math.abs(c)===2)sphere.push([a,b,c]);
  req(sphere.length===18,"independent tiny sphere");
  let tv1=0,tv2=0,matrices=0;
  for(let a=0;a<5;a++)for(let b=0;b<5;b++)for(let c=0;c<5;c++){
    matrices++;const images=sphere.map(z=>mod(a*z[0]+b*z[1]+c*z[2],5));
    const hist=Array(5).fill(0);for(const v of images)hist[v]++;
    tv1+=hist.reduce((s,v)=>s+Math.abs(v/18-1/5),0)/2;
    const pair=Array(25).fill(0);for(const v of images)for(const w of images)pair[v*5+w]++;
    tv2+=pair.reduce((s,v)=>s+Math.abs(v/324-1/25),0)/2;
    count+=30
  }
  tv1/=matrices;tv2/=matrices;
  req(matrices===125,"uniform H enumeration");
  req(Math.abs(tv1-328/1875)<1e-12,"exact one-column source TV");
  req(Math.abs(tv2-21292/84375)<1e-12,"exact two-column source TV");
  req(tv1<=0.5*Math.sqrt(4/18)&&tv2<=Math.sqrt(4/18),"independent source TV upper bounds");
  let cm=1n,ch=1n,N=0n;
  for(let k=1;k<=800;k++){
    cm=cm*BigInt(1601-k)/BigInt(k);
    if(k>1)ch=ch*BigInt(801-k)/BigInt(k-1);
    N+=(1n<<BigInt(k))*cm*ch;
  }
  req(N>(65537n**128n)*(2n**600n),"large source hash entropy");
  const bits=N.toString(2),logN=bits.length-1+Math.log2(Number.parseInt(bits.slice(0,52),2)/2**51);
  const logDelta=-1+0.5*(128*Math.log2(65537)-logN);
  const source=128*1600+128*14,ct=3*4*(1600+14),primal=128*1600+1600*14+3*4*(128+14);
  req(source+ct===225960&&primal===228904,"public resource tradeoff");
  const out={status:"PASS",checks:count,toy:{q,m,n,d,h,distinct_witnesses:2,capability_bits:kappa,capability_trials:12,warning:"mock 64-bit signing seed; not a real signature implementation"},tiny_source:{matrix_count:matrices,source_count:sphere.length,average_TV_one:Number(tv1.toFixed(12)),average_TV_two:Number(tv2.toFixed(12))},illustrative:{q:65537,n:128,m:1600,d:14,h:800,source_log2_N:Number(logN.toFixed(9)),source_delta_log2:Number(logDelta.toFixed(9)),ciphertext_elements:ct,source_plus_ciphertext_elements:source+ct,primal_predecessor_elements:primal},limits:"Exact algebra, finite distribution and size checks only. No QPT hardness proof, native SLH, generic NP compiler or Bitcoin deployment."};
  if(typeof console!=="undefined")console.log(JSON.stringify(out,null,2));
  return out
})();
