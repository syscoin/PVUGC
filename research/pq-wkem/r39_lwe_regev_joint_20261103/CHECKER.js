const report = (function checker() {
  let assertions=0,seed=39039;
  const check=(v,m)=>{if(!v)throw Error(m);assertions++};
  const rnd=(max)=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%max};
  const sm=(x,q)=>((x%q)+q)%q;
  // All 6561 public seeds for the q=3,n=1,m=4 strong leftover hash example.
  let seedCount=0,numTotal=0,maxNumer=0;
  for(let a0=0;a0<81;a0++)for(let b0=0;b0<81;b0++){
    let av=a0,bv=b0,A=[],B=[];
    for(let j=0;j<4;j++){A.push(av%3);av=Math.floor(av/3);B.push(bv%3);bv=Math.floor(bv/3)}
    const count=Array(9).fill(0);
    for(let r=0;r<16;r++){
      let u=0,v=0;for(let j=0;j<4;j++)if(r&(1<<j)){u+=A[j];v+=B[j]}
      count[sm(u,3)*3+sm(v,3)]++;
    }
    check(count.reduce((a,b)=>a+b,0)===16,"hash preimage size");
    const numer=count.reduce((z,c)=>z+Math.abs(9*c-16),0);
    numTotal+=numer;maxNumer=Math.max(maxNumer,numer);seedCount++;
  }
  check(seedCount===6561&&numTotal===515840,"exact leftover hash TV");
  const q=257,m=16,Delta=128;
  const A0=Array.from({length:m},()=>rnd(q));
  const A1=Array(m).fill(0),s0=[19,23],s1=[19,40];
  const e=Array.from({length:m},(_,j)=>(j%3)-1);
  const b=A0.map((x,j)=>sm(x*s0[0]+e[j],q));
  const valid=s=>b.every((x,j)=>Math.abs(sm(x-A0[j]*s[0]-A1[j]*s[1]+q/2,q)-q/2)<=1);
  // Evaluate an alternate exact centered-residual test rather than relying on floating half.
  const centered=t=>{t=sm(t,q);return t>q/2?t-q:t};
  check([s0,s1].every(s=>b.every((x,j)=>Math.abs(centered(x-A0[j]*s[0]-A1[j]*s[1]))<=1)),"both distinct valid witnesses");
  check(s0[1]!==s1[1]&&m*1<Delta/2,"distinct, bounded source witnesses");
  const H=x=>Math.imul((x>>>0)^0x9e3779b9,2654435761)>>>0; // insecure fixture
  const sk=Array.from({length:8},()=>[rnd(2**30),rnd(2**30)]);
  const vk=sk.map(pair=>pair.map(H));
  let mhash=0x39;
  for(let j=0;j<m;j++)mhash=H(mhash^A0[j]^b[j]);
  for(const pair of vk)for(const value of pair)mhash=H(mhash^value);
  const mbits=Array.from({length:8},(_,j)=>(mhash>>>j)&1);
  const signature=sk.map((pair,j)=>pair[mbits[j]]);
  const verify=sig=>sig.length===8&&sig.every((x,j)=>H(x)===vk[j][mbits[j]]);
  check(verify(signature),"toy presignature");
  const key=Array.from({length:16},()=>rnd(256));
  let state=key.reduce((acc,x)=>H(acc^x),0x13579bdf);
  const pad=Array.from({length:32},()=>{state=H(state);return state&255});
  const sigmaBytes=signature.flatMap(x=>[x&255,(x>>>8)&255,(x>>>16)&255,(x>>>24)&255]);
  const D=sigmaBytes.map((x,j)=>x^pad[j]);
  const bits=key.flatMap(x=>Array.from({length:8},(_,j)=>(x>>j)&1));
  let success=0;const scopes=[];
  for(let scope=0;scope<2;scope++){
    const cts=bits.map(bit=>{
      const r=Array.from({length:m},()=>rnd(2));
      return [[sm(A0.reduce((z,x,j)=>z+x*r[j],0),q),0],sm(b.reduce((z,x,j)=>z+x*r[j],0)+Delta*bit,q)];
    });
    scopes.push(cts);
    for(const s of [s0,s1]){
      const recovered=cts.map(([u,v])=>{
        const z=sm(v-s[0]*u[0]-s[1]*u[1],q);
        const dist=x=>Math.min(sm(z-x,q),sm(x-z,q));
        return Number(dist(Delta)<dist(0));
      });
      for(let j=0;j<bits.length;j++){check(recovered[j]===bits[j],"bit decodes");success++}
      const K=Array.from({length:16},(_,j)=>recovered.slice(j*8,j*8+8).reduce((z,t,k)=>z+(t<<k),0));
      check(K.every((x,j)=>x===key[j]),"same shared K");
      let s2=K.reduce((acc,x)=>H(acc^x),0x13579bdf);
      const pad2=Array.from({length:32},()=>{s2=H(s2);return s2&255});
      const recoveredSig=D.map((x,j)=>x^pad2[j]);
      check(recoveredSig.every((x,j)=>x===sigmaBytes[j]),"same presignature");
    }
  }
  let ck=0x3f;
  for(const n of [...D,...vk.flat(),...scopes.flat().flatMap(([u,v])=>[...u,v])])ck=H(ck^n);
  const aux=H(ck^0xdeadbeef);
  check(ck!==aux,"public CK and aux");
  // A malicious FALSE key (A=0, b_0=2, B=1) exposes each bit by disjoint v bands.
  for(const bit of [0,1])for(const r0 of [0,1]){
    const v=(2*r0+Delta*bit)%q;
    check(Number(v>=Delta)===bit,"false statement leak");
  }
  return {run:"R39-LWE-REGEV-JOINT-SOURCE-20261103",checks:assertions,
    leftover:{q:3,n:1,m:4,seeds:seedCount,binary_inputs:16,
      average_TV_num:numTotal,average_TV_den:288*seedCount,upper_bound:0.375,
      max_conditional_TV:maxNumer/288},
    surrogate_true:{q:257,n:2,m:16,B:1,distinct_witnesses:2,
      scopes:2,encrypted_key_bits:bits.length,bit_ciphertexts:bits.length*2,
      same_key_decodings:success,signature_bytes:32,dem_bytes:D.length,CK:ck,aux},
    adversarial_false:"A=0,b0=2,B=1 permits perfect plaintext-bit recovery",
    caution:"test hash and PRG are insecure; no QPT or generic-NP claim"};
})();
console.log(JSON.stringify(report,null,2));
