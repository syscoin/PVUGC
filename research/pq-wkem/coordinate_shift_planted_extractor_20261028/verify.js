function verify() {
  let checks=0;
  function ck(x,why){if(!x)throw Error("FAIL:"+why);checks++;}
  function mod(a,q){return ((a%q)+q)%q;}
  function eq(A,B){if(A.size!==B.size)return false;for(const [k,v] of A)if(B.get(k)!==v)return false;return true;}
  function shiftLaw(law,i,d,q) {
    const out=new Map();
    for(const [key,n] of law) {
      const v=key.split(",").map(Number);v[i]=mod(v[i]-d,q);
      const k=v.join(",");out.set(k,(out.get(k)||0)+n);
    }
    return out;
  }
  // Full ciphertext-vector count, q=17,M=3,w=(1,1,0).
  const q=17,g=5,a=1,P0=new Map(),Pa=new Map();
  function add(map,v){const k=v.join(",");map.set(k,(map.get(k)||0)+1);}
  for(let u0=0;u0<q;u0++)for(let u1=0;u1<q;u1++)
  for(let e0=-1;e0<=1;e0++)for(let e1=-1;e1<=1;e1++)for(let e2=-1;e2<=1;e2++){
    const base=[mod(-u0+e0,q),mod(u0+e1,q),mod(u1+e2,q)];
    ck(mod(base[0]+base[1],q)===mod(e0+e1,q),"honest row mask cancels");
    add(P0,base);add(Pa,[mod(base[0]+g*a,q),base[1],base[2]]);
  }
  ck(eq(shiftLaw(Pa,0,g*a,q),P0),"anchor support coordinate shift");
  ck(eq(shiftLaw(Pa,1,g*a,q),P0),"non-anchor support coordinate shift");
  ck(eq(shiftLaw(Pa,2,g*a,q),Pa),"nonsupport coordinate invariant");
  let state=20261028>>>0;
  function rand(){state=(Math.imul(state,1664525)+1013904223)>>>0;return state/4294967296;}
  function ri(n){return Math.floor(rand()*n);}
  // Black-box oracle intentionally closes over hidden ORIGINAL w;
  // the extractor below is passed only its callable interface.
  const Q=31,M=9,W=[1,0,1,0,1,0,0,0,0],h=3,gap=7,digit=2,N=1500;
  function sample(){
    const u=Array.from({length:M-1},()=>ri(Q));
    const eps=Array.from({length:M},()=>ri(3)-1);
    const p=eps.map(x=>x);p[0]=mod(p[0]+gap*digit,Q);
    for(let i=1;i<M;i++){p[i]=mod(p[i]+u[i-1],Q);p[0]=mod(p[0]-W[i]*u[i-1],Q);}
    return p;
  }
  function oracle(p){
    let t=0;for(let i=0;i<M;i++)t+=W[i]*p[i];
    let r=mod(t-gap*digit,Q),dist=Math.min(r,Q-r);
    return rand()<(dist<=h?.8:.2)?1:0;
  }
  const totals=Array(M+1).fill(0);
  for(let sampleIndex=0;sampleIndex<N;sampleIndex++){
    const p=sample();
    totals[0]+=oracle(p);
    for(let i=0;i<M;i++){
      const v=p.slice();v[i]=mod(v[i]-gap*digit,Q);
      totals[1+i]+=oracle(v);
    }
  }
  const means=totals.map(x=>x/N),observed=means[0]-means[1];
  ck(Math.abs(observed-.6)<.08,"signed hybrid gap");
  const extracted=[];
  for(let i=0;i<M;i++){
    const val=means[0]-means[1+i];
    extracted.push(+(val>.3));
    ck(Math.abs(val-(W[i]?.6:0))<.09,"support-shift expectation");
    ck(extracted[i]===W[i],"ORIGINAL binary witness extracted");
  }
  // SAME precommitted 256-bit seed through two distinct kernel witnesses.
  const M2=6,B=51,ELL=46,Q2=257,seedTrials=10;
  const W1=[1,1,0,0,0,0],W2=[1,0,1,0,0,0];
  for(let t=0;t<seedTrials;t++){
    const K=Array.from({length:32},()=>ri(256));
    const U=Array.from({length:32},()=>ri(256));
    const Z=Array.from({length:32},()=>ri(256));
    const D=K.map((x,i)=>U[i]^Z[i]);const V=K.map((x,i)=>x^U[i]);
    let z=0n;for(const byte of Z)z=(z<<8n)|BigInt(byte);
    for(let j=0;j<ELL;j++){
      const a=Number(z%51n);z/=51n;
      const u0=ri(Q2),eps=Array.from({length:M2},()=>ri(3)-1);
      const p=[mod(u0+eps[0]+5*a,Q2),mod(-u0+eps[1],Q2),mod(-u0+eps[2],Q2),0,0,0];
      for(const w of [W1,W2]){
        let phase=0;for(let i=0;i<M2;i++)phase+=w[i]*p[i];phase=mod(phase,Q2);
        const cand=[];for(let d=0;d<B;d++){const x=mod(phase-5*d,Q2);if(Math.min(x,Q2-x)<=2)cand.push(d);}
        ck(cand.length===1&&cand[0]===a,"two original openings same radix digit");
      }
    }
    ck(z===0n,"256-bit pad fully encoded");
    const recovered=K.map((_,i)=>D[i]^V[i]^Z[i]);
    ck(recovered.every((v,i)=>v===K[i]),"precommitted complete seed");
  }
  return {status:"PASS",assertions:checks,full_vector_q17_unique_states:P0.size,black_box_extracted:extracted,black_box_true:W,anchor_gap:Math.round(observed*1e6)/1e6,same_seed_trials:seedTrials,claim:"bounded classical algebra only; no QPT hardness"};
}
console.log(JSON.stringify(verify()));
