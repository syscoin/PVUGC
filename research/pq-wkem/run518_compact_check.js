// Run 518: exact interface checks and finite-state quantum-search amplitudes.
// Research fixtures, not a practical protected mixer or PQ proof.
'use strict';
let nFrames=0,nRecover=0,nFixed=0,nGrover=0;
let r=518;
const rnd=()=>{r^=r<<13;r^=r>>>17;r^=r<<5;return r>>>0;};
for(const [ell,marked] of [[3,[1]],[4,[2,7]],[5,[3,9,15,25]]]){
  const h=2,key=3,N=1<<(h+ell+1),p=Array.from({length:N},(_,i)=>i);
  for(let j=N-1;j>0;j--){const k=rnd()%(j+1);[p[j],p[k]]=[p[k],p[j]];}
  const inv=Array(N);p.forEach((v,i)=>inv[v]=i);
  const pack=(k,s,t)=>(((k<<ell)|s)<<1)|t;
  const unpack=y=>[y>>(ell+1),(y>>1)&((1<<ell)-1),y&1];
  const loader=(y,j)=>{const [k,s,t]=unpack(inv[y]);return p[pack(k,s^(1<<j),t)];};
  const term=(y,i)=>{const [k,s,t]=unpack(inv[y]);return p[pack(k,s,t^(((k>>i)&1)*Number(marked.includes(s))))];};
  const anchor=p[pack(key,0,0)];
  const encode=s=>{let y=anchor;for(let j=0;j<ell;j++)if((s>>j)&1)y=loader(y,j);return y;};
  for(let s=0;s<(1<<ell);s++){
    const y=encode(s),bits=Array.from({length:h},(_,i)=>Number(term(y,i)!==y));
    if(bits.some(v=>v!==Number(marked.includes(s))))throw Error('mark mismatch');
    nFrames++;
    if(marked.includes(s)){
      if(bits.reduce((a,b,i)=>a+(b<<i),0)!==key)throw Error('false-target key mismatch');
      nRecover++;
    } else nFixed+=h;
  }
}
for(let ell=3;ell<=6;ell++)for(const M of [1,2,4]){
 const N=1<<ell,theta=Math.asin(Math.sqrt(M/N));let a=Array(N).fill(1/Math.sqrt(N));
 for(let t=0;t<5;t++){
  const prob=a.slice(0,M).reduce((v,x)=>v+x*x,0),want=Math.sin((2*t+1)*theta)**2;
  if(Math.abs(prob-want)>3e-12)throw Error('Grover amplitude mismatch');
  nGrover++;
  const phased=a.map((v,i)=>i<M?-v:v),avg=phased.reduce((x,y)=>x+y,0)/N;
  a=phased.map(v=>2*avg-v);
 }
}
const result={run:518,status:'PASS',opaque_frame_points:nFrames,false_target_key_recoveries:nRecover,nonmarked_fixed_bits:nFixed,grover_amplitude_checks:nGrover,quantum_hardware:false,practical_security_proved:false};
console.log(JSON.stringify(result,null,2));
