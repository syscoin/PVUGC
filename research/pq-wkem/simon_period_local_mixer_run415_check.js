// Run 415 exact finite XOR-period/Simon's-algorithm negative control.
// Deterministic classical simulation of QPT measurements; NOT a QPT hardness test.
function runCheck() {
 let checks=0,seed=41520261010>>>0;
 const ok=(b,why)=>{checks++;if(!b)throw Error(why)};
 const next=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0};
 const parity=x=>{let p=0;while(x){p^=1;x&=x-1}return p};
 const rank=(v)=>{let basis={};for(let t of v){while(t){let j=31-Math.clz32(t);if(basis[j]===undefined){basis[j]=t;break}t^=basis[j]}}return Object.keys(basis).length};
 const oracle=(n,s)=>{const N=1<<n,a=Array.from({length:N},(_,i)=>i);for(let i=N-1;i>0;i--){const j=next()%(i+1);[a[i],a[j]]=[a[j],a[i]]}return x=>a[Math.min(x,x^s)]};
 let promises=0,spectra=0,simons=0,falseKeys=0;
 for(let n=2;n<=6;n++){const N=1<<n;
  for(let s=1;s<N;s++){const f=oracle(n,s);
   for(let u=0;u<N;u++)for(let v=0;v<N;v++){
    ok((f(u)===f(v))===(v===u||v===(u^s)),"extra/absent XOR collision");promises++;}
   let mass=0;const x=next()%N;
   for(let y=0;y<N;y++){const a=(parity(x&y)?-1:1)+(parity((x^s)&y)?-1:1);
    const expected=parity(s&y)?0:4;ok(a*a===expected,"wrong exact Hadamard mass");mass+=a*a;spectra++;}
   ok(mass===2*N,"non-normalized Simon distribution");
  }
 }
 for(let n=2;n<=8;n++){const N=1<<n;
  for(let t=0;t<128;t++){
   const s=1+next()%(N-1),support=[];
   for(let y=0;y<N;y++)if(!parity(y&s))support.push(y);
   const ys=Array.from({length:n+18},()=>support[next()%support.length]);
   const candidates=[];
   for(let r=1;r<N;r++)if(ys.every(y=>!parity(y&r)))candidates.push(r);
   ok(candidates.length===1&&candidates[0]===s,"Simon's linear period extraction failed");simons++;
  }
 }
 for(let t=0;t<256;t++){const N=256,K=next()%N,a0=1+next()%(N-1);let a1=1+next()%(N-1);if(a0===a1)a1=a1%255+1;
  const Y0=K^a0,Y1=K^a1;
  const src=Array.from({length:N},(_,j)=>j);for(let i=N-1;i>0;i--){const j=next()%(i+1);[src[i],src[j]]=[src[j],src[i]]}
  const h0=src[a0],h1=src[a1],R=(b,i,w)=>b===1&&i>=0&&i<2&&src[w]===(i===0?h0:h1);
  ok(R(1,0,a0)&&R(1,1,a1),"two witnesses rejected");
  ok(!R(0,0,a0)&&!R(0,1,a1),"false relation has witnesses");
  ok((Y0^a0)===K&&(Y1^a1)===K,"all-witness same-K failed");
  const s=a0,support=[];for(let y=0;y<N;y++)if(!parity(y&s))support.push(y);
  const ys=Array.from({length:36},()=>support[next()%support.length]);
  const guess=Array.from({length:N-1},(_,i)=>i+1).filter(r=>ys.every(y=>!parity(y&r)));
  ok(guess.length===1&&guess[0]===s&&((Y0^guess[0])===K),"false-instance recovered K mismatch");falseKeys++;
 }
 return {run:415,assertions:checks,promise_pair_cases:promises,hadamard_exact_cases:spectra,
  simulated_simons:simons,all_witness_same_K_cases:falseKeys,false_original_instance_key_recoveries:falseKeys,
  scope:"Finite algebra and ideal Simon samples; no concrete WE, obfuscation, PQ or Bitcoin implementation"};
}

