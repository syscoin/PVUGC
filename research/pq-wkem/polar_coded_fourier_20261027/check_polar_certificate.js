'use strict';
// Self-contained exact-integer polar completeness certificate and finite SC test.
// Scope: correctness/size only. False-source distribution proved in README and
// independently checked in the longer local Python checker.
let checks=0;const ok=(b,m)=>{if(!b)throw Error(m);checks++};
function isqrt(n){if(n<2n)return n;let x=1n<<BigInt(Math.ceil(n.toString(2).length/2));for(;;){const y=(x+n/x)>>1n;if(y>=x)return x;x=y}}
function synthesized(n,z,D){
 if(n===1)return [z];
 const minus=(2n*z-(z*z)/D)>D?D:2n*z-(z*z)/D;
 const plus=((z*z+D-1n)/D)>D?D:(z*z+D-1n)/D;
 const lo=synthesized(n/2,minus,D),hi=synthesized(n/2,plus,D),out=[];
 for(let j=0;j<lo.length;j++)out.push(lo[j],hi[j]);return out;
}
function certify(k,t,lam,num,den,limit){
 const P=t+lam+128,D=1n<<BigInt(P),a=BigInt(num),b=BigInt(den);
 const z0=isqrt(((b*b-a*a)*D*D)/(b*b))+1n;
 for(let n=1;n<=limit;n*=2){
  if(n<k)continue;
  const values=synthesized(n,z0,D);
  const inds=Array.from({length:n},(_,i)=>i).sort((i,j)=>values[i]<values[j]?-1:values[i]>values[j]?1:i-j).slice(0,k);
  const sum=inds.reduce((s,i)=>s+values[i],0n);
  if((sum<<BigInt(t+lam))<=D){
   ok(inds.length===k&&new Set(inds).size===k,'distinct information positions');
   ok(sum<<BigInt(t+lam)<=D,'public exact completeness certificate');
   return {rho:`${num}/${den}`,N:n,info:inds.sort((a,b)=>a-b),log2Zfloor:sum.toString(2).length-1-P};
  }
 }throw Error('length cap exceeded');
}
function enc(u){if(u.length===1)return u.slice();const a=enc(u.filter((_,j)=>j%2===0)),b=enc(u.filter((_,j)=>j%2===1));return a.map((x,i)=>x^b[i]).concat(b)}
function f(a,b){const t=Math.tanh(a/2)*Math.tanh(b/2);if(Math.abs(t)<0.999999999999)return Math.log((1+t)/(1-t));const A=Math.abs(a),B=Math.abs(b);const x=Math.min(A,B)+Math.log1p(Math.exp(-A-B))-Math.log1p(Math.exp(-Math.abs(A-B)));return (a>=0)===(b>=0)?x:-x}
function dec(llr,frozen){
 function go(a,fr){if(a.length===1){const v=fr[0]>=0?fr[0]:(a[0]>=0?0:1);return [[v],[v]]}const n=a.length/2;
  const l=Array.from({length:n},(_,i)=>f(a[i],a[i+n])),[u,A]=go(l,fr.filter((_,j)=>j%2===0));
  const rr=Array.from({length:n},(_,i)=>a[i+n]+(1-2*A[i])*a[i]),[v,B]=go(rr,fr.filter((_,j)=>j%2===1));
  const out=[];for(let i=0;i<n;i++)out.push(u[i],v[i]);return [out,A.map((x,i)=>x^B[i]).concat(B)]}
 return go(llr,frozen)[0];
}
function finiteSC(){
 const n=8,info=[3,7],p=1/6,fr=Array.from({length:n},(_,i)=>info.includes(i)?-1:0),weights=[];
 for(let i=0;i<=n;i++)weights.push(5n**BigInt(n-i));
 const error=[];
 for(let key=0;key<4;key++){
  const u=Array(n).fill(0);for(let j=0;j<2;j++)u[info[j]]=(key>>j)&1;
  const c=enc(u);let wt=0n;
  for(let mask=0;mask<(1<<n);mask++){
   const y=c.map((x,i)=>x^((mask>>i)&1));
   const got=dec(y.map(b=>(1-2*b)*Math.log(5)),fr);
   if(got.some((v,i)=>v!==u[i])){let bad=0;for(let i=0;i<n;i++)bad+=(mask>>i)&1;wt+=weights[bad]}
  }
  error.push(wt);
 }
 const avgNum=error.reduce((x,y)=>x+y,0n),den=4n*6n**8n;
 for(let K=0;K<4;K++){
  const ditherSum=Array.from({length:4},(_,S)=>error[K^S]).reduce((x,y)=>x+y,0n);
  ok(ditherSum===avgNum,'uniform public dither makes fixed-K error uniform');
 }
 ok(avgNum*729n===104n*den,'exact enumerated dithered BSC(1/6) rate');
 return {N:n,k:2,publicDitheredError:'104/729',individualErrorNumerators:error.map(String)};
}
const a=certify(256,256,128,2,3,65536),b=certify(256,256,128,1,2,65536);
ok(a.N===16384,'single gate sample certified N');ok(b.N===32768,'half-bias sample certified N');
const finite=finiteSC();
console.log(JSON.stringify({status:'PASS',checks,run:'polar-coded-fourier-20261027-automation5',
 certified:[{rho:a.rho,N:a.N,log2Zfloor:a.log2Zfloor},{rho:b.rho,N:b.N,log2Zfloor:b.log2Zfloor}],finite},null,2));
