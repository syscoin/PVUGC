'use strict';
// Exact finite Simon-promise Fourier test; not scalable encryption or a quantum implementation.
let checks=0;
const parity=x=>{let v=x,b=0;while(v){b^=v&1;v>>=1;}return b;};
const cases=[];
for(let n=3;n<=8;n++){
 const N=1<<n,delta=(1<<(n-2))|1;
 const f=x=>Math.min(x,x^delta);
 for(let x=0;x<N;x++){
  if(f(x)!==f(x^delta))throw Error('period');checks++;
  for(let y=0;y<N;y++){
   const amp=((parity(x&y)?-1:1)+(parity((x^delta)&y)?-1:1))/Math.sqrt(2*N);
   const want=parity(delta&y)?0:2/N;
   if(Math.abs(amp*amp-want)>1e-12)throw Error('Fourier');checks++;
  }
 }
 const periods=[];
 for(let d=1;d<N;d++)if(Array.from({length:N},(_,x)=>f(x)===f(x^d)).every(Boolean))periods.push(d);
 if(periods.length!==1||periods[0]!==delta)throw Error('unique period');checks++;
 cases.push({n,delta,unique_period:true,forbidden_fourier_mass:0});
}
process.stdout.write(JSON.stringify({run:493,checks,cases,scope:'finite exact Fourier test; no public PPT mixer or cryptographic security'},null,2)+'\n');
