'use strict';
// Run 569: reproducible finite algebra; NOT a QPT or random-oracle implementation.
function insist(v, m) { if (!v) throw Error(m); counts.assertions++; }
function parity(z) { z ^= z >>> 16; z ^= z >>> 8; z ^= z >>> 4; z &= 15; return (0x6996 >>> z) & 1; }
function rng(seed) { let s=seed>>>0; return () => {s^=s<<13;s^=s>>>17;s^=s<<5; return s>>>0;}; }
function rank(rows,n) {
  const a=rows.slice();let r=0;
  for(let j=0;j<n;j++) {
    let idx=-1;for(let k=r;k<a.length;k++) if((a[k]>>>j)&1){idx=k;break;}
    if(idx<0)continue;
    [a[r],a[idx]]=[a[idx],a[r]];
    for(let k=0;k<a.length;k++)if(k!==r&&((a[k]>>>j)&1))a[k]^=a[r];
    r++;
  }
  return r;
}
function solveShift(rows,n) {
  let mat=rows.map(y=>[y&((1<<n)-1),(y>>>n)&1]);let k=0,piv=[];
  for(let b=0;b<n;b++){
    let h=-1;for(let j=k;j<mat.length;j++)if((mat[j][0]>>>b)&1){h=j;break;}
    if(h<0)continue;
    [mat[k],mat[h]]=[mat[h],mat[k]];
    for(let j=0;j<mat.length;j++)if(j!==k&&((mat[j][0]>>>b)&1)){
      mat[j][0]^=mat[k][0];mat[j][1]^=mat[k][1];
    }
    piv.push(b);k++;
  }
  if(k!==n)return null;
  let x=0;for(let j=0;j<n;j++)if(mat[j][1])x|=(1<<piv[j]);
  return x;
}
const counts={run:569,status:'PASS',assertions:0,configurations:0,hidden_shift_recoveries:0,first_layer_nonperiodic:0,coset_checks:0,fourier_cancellations:0,oracle_values_checked:0,coherent_queries_executed:0};
for(let n=3;n<=8;n++) for(let trial=1;trial<=7;trial++){
  const N=1<<n, rand=rng((0x9e3779b9 ^ (n*104729) ^ (trial*65537))>>>0);
  const shift=1+(rand()%(N-1));
  const A=[],B=[], seen=new Set();
  for(let s=0;s<N;s++) A.push(rand());
  for(let s=0;s<N;s++){
    let y=rand();while(seen.has(y))y=rand();seen.add(y);B.push(y);
  }
  const F=Array.from({length:N},(_,s)=>(A[s]^B[s^shift])>>>0);
  // Its single exposed layer almost always has NO Simon period.
  const hasNonzeroPeriod=Array.from({length:N-1},(_,j)=>j+1).some(d=>F.every((v,s)=>v===F[s^d]));
  insist(!hasNonzeroPeriod,'unexpected fixture F period');counts.first_layer_nonperiodic++;
  const G=F.map((v,s)=>(v^A[s])>>>0);
  for(let s=0;s<N;s++) {insist(G[s]===B[s^shift],'peeling');counts.oracle_values_checked++;}
  // Combined two-layer oracle has hidden period (shift,1).
  const J=Array.from({length:2*N},(_,u)=>u<N? B[u] : G[u-N]);
  const p=shift|N;
  const fibers=new Map();
  for(let u=0;u<2*N;u++){
    insist(J[u]===J[u^p],'hidden period');
    const v=J[u]; if(!fibers.has(v))fibers.set(v,[]);fibers.get(v).push(u);
    counts.oracle_values_checked++;
  }
  insist(fibers.size===N,'injective B');
  for(const fiber of fibers.values()){
    insist(fiber.length===2 && (fiber[0]^fiber[1])===p,'exact two-to-one');counts.coset_checks++;
    // Simon measurement amplitude has exact cancellation if <y,p>=1.
    for(let y=0;y<2*N;y++){
      const amp=(parity(fiber[0]&y)?-1:1)+(parity(fiber[1]&y)?-1:1);
      insist((parity(y&p)===1 && amp===0)||(parity(y&p)===0 && Math.abs(amp)===2),'Fourier cancellation');
      counts.fourier_cancellations++;
    }
  }
  // Analytically simulated Simon samples (not quantum hardware).
  const rows=[];for(let z=0;z<n+24;z++){
    const a=rand()&(N-1);
    const y=a|(parity(a&shift)<<n);
    insist(parity(y&p)===0,'sample orthogonality');rows.push(y);
  }
  insist(rank(rows,n+1)===n,'Simon sample rank');
  const recovered=solveShift(rows,n);
  insist(recovered===shift,'shift extraction');counts.hidden_shift_recoveries++;
  counts.configurations++;
}
counts.note='Random-looking deterministic toy arrays and analytically simulated Simon measurements only. No cryptographic implementation or proof of QPT security.';
console.log(JSON.stringify(counts,null,2));
