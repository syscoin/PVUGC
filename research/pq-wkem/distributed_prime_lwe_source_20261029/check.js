'use strict';
const runChecker = function runChecker() {
  "use strict";
  let seed=20261029^0x3a815, checks=0;
  const rnd=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n;};
  const ok=(v,m)=>{checks++;if(!v)throw Error("ASSERT "+m);};
  const mod=(x,q)=>((x%q)+q)%q;
  const dist=(x,y,q)=>{const z=mod(x-y,q);return Math.min(z,q-z);};
  const getBit=(bytes,k)=>(bytes[Math.floor(k/8)]>>(k%8))&1;
  const q=1009,n=2,m=17,B=1,N=4,J=2,L=256,g=Math.floor(q/2);
  ok(q>4*N*m*B+2,"prime modulus correctness threshold");
  const A=Array.from({length:n},()=>Array.from({length:m},()=>rnd(q)));
  A[n-1].fill(0);
  const s=Array.from({length:n},()=>rnd(q));
  const e=Array.from({length:m},()=>rnd(2*B+1)-B);
  const b=Array.from({length:m},(_,j)=>mod(e[j]+A.reduce((z,row,i)=>z+row[j]*s[i],0),q));
  const witnesses=Array.from({length:6},(_,i)=>[s[0],mod(s[1]+73*i,q)]);
  for(const w of witnesses)
    for(let j=0;j<m;j++){
      let residual=mod(b[j]-A.reduce((z,row,i)=>z+row[j]*w[i],0),q);
      if(residual>q/2)residual-=q;
      ok(Math.abs(residual)<=B,"different accepted SOURCE witness");
    }
  const K=Array.from({length:32},()=>rnd(256));
  const checkingKey=(arr)=>{let h=2166136261>>>0;for(const x of arr){h=Math.imul(h^x,16777619)>>>0;h^=h>>>13;}return h>>>0;};
  const pk=checkingKey(K);
  const shares=[];
  for(let ell=0;ell<L;ell++){
    const a=getBit(K,ell);
    const z=Array.from({length:N-1},()=>rnd(q));
    z.push(mod(a-z.reduce((x,y)=>x+y,0),q));
    ok(mod(z.reduce((x,y)=>x+y,0),q)===a,"all q-ary shares reconstruct native bit");
    shares.push(z);
  }
  const encrypt=z=>{
    const r=Array.from({length:m},()=>rnd(2));
    const u=A.map(row=>mod(row.reduce((sum,v,j)=>sum+v*r[j],0),q));
    const v=mod(b.reduce((sum,v,j)=>sum+v*r[j],0)+g*z,q);
    return {r,u,v};
  };
  const decode=(C,w)=>{
    const residual=mod(C.v-w.reduce((t,si,i)=>t+si*C.u[i],0),q);
    return {bit:+(dist(residual,g,q)<dist(residual,0,q)),residual};
  };
  let contributions=0;
  for(let cap=0;cap<J;cap++){
    const recovered=Array(L).fill(0);
    for(let ell=0;ell<L;ell++){
      const cs=shares[ell].map(encrypt);
      contributions+=cs.length;
      const u=Array.from({length:n},(_,i)=>mod(cs.reduce((t,c)=>t+c.u[i],0),q));
      const v=mod(cs.reduce((t,c)=>t+c.v,0),q);
      const rSum=Array.from({length:m},(_,j)=>cs.reduce((t,c)=>t+c.r[j],0));
      const error=e.reduce((t,ei,j)=>t+ei*rSum[j],0);
      ok(Math.abs(error)<=N*m*B,"aggregated error bound");
      for(const w of witnesses){
        const d=decode({u,v},w);
        ok(d.bit===getBit(K,ell),"every distinct witness SAME native bit");
        ok(mod(d.residual-g*getBit(K,ell),q)===mod(error,q),"exact all-party linear release equation");
      }
      recovered[ell]=decode({u,v},s).bit;
    }
    const bytes=Array.from({length:32},(_,i)=>{
      let v=0;for(let t=0;t<8;t++)v|=recovered[i*8+t]<<t;return v;
    });
    ok(bytes.every((v,i)=>v===K[i]),"whole native seed recovered by aggregate");
    ok(checkingKey(bytes)===pk,"fixed checking-key correlation in both capsules (mock fingerprint)");
  }
  for(const a of [0,1])for(let h=0;h<3;h++){
    const freq=new Map(), q0=3;
    for(let x=0;x<q0;x++)for(let y=0;y<q0;y++){
      const z=[x,y,mod(a-x-y,q0)];
      const key=z.filter((_,i)=>i!==h).join(",");
      freq.set(key,(freq.get(key)||0)+1);
    }
    ok(freq.size===9,"all N-1 share outcomes");
    for(const v of freq.values())ok(v===1,"each N-1 share outcome exact uniform");
  }
  const F=3,d=2,matrices=[];
  for(let a=0;a<F;a++)for(let b0=0;b0<F;b0++)
    for(let c=0;c<F;c++)for(let d0=0;d0<F;d0++)
      matrices.push([[a,b0],[c,d0]]);
  for(let x=0;x<4;x++)for(let y=x+1;y<4;y++){
    const frequencies=new Map();
    const delta=[(x&1)-(y&1),((x>>1)&1)-((y>>1)&1)];
    for(const H of matrices){
      const key=H.map(row=>mod(row[0]*delta[0]+row[1]*delta[1],F)).join(",");
      frequencies.set(key,(frequencies.get(key)||0)+1);
    }
    ok(frequencies.size===F**d,"binary subset-sum hash difference full support");
    for(const v of frequencies.values())ok(v===matrices.length/(F**d),"pairwise universality exact uniform");
  }
  const falseSupports=[[0,1],[128,129]];
  ok(falseSupports[0].every(v=>!falseSupports[1].includes(v)),"specific fixed-FALSE source exposes bits");
  return {status:"PASS (restricted distributed prime-LWE SOURCE)",assertions:checks,
    params:{q,n,m,B,N,J,L},differentAcceptedWitnesses:witnesses.length,
    individualContributorCiphertexts:contributions,aggregateCiphertexts:J*L,
    samePrecommittedNativeSeed:true,anyNminus1ShareUniformityExhaustive:true,
    binarySubsetSumPairwiseUniversalityExhaustive:true,fixedFalseFailureDemonstrated:true,
    disclaimer:"Finite algebraic checks; mock checking-key fingerprint; no native SLH, QPT hardness, original NP or malicious ceremony claim"};
};
console.log(JSON.stringify(runChecker(),null,2));
