'use strict';
// Run 435: exact finite check of complementary constant-rate corruption.
// Diagnostic Simon Fourier distributions; NO real quantum device or WKEM.
let checks = 0;
function ok(a,why){checks++;if(!a)throw Error(why)}
function parity(x){let b=0;while(x){b^=1;x&=x-1}return b}
function spectrum(g,n){
  const N=1<<n, groups=new Map(), out=[];
  for(let x=0;x<N;x++){
    const key=g[x];if(!groups.has(key))groups.set(key,[]);
    groups.get(key).push(x);
  }
  for(let y=0;y<N;y++){
    let z=0;
    for(const xs of groups.values()){
      let v=0;for(const x of xs)v+=parity(x&y)?-1:1;
      z+=v*v;
    }
    out.push(z);
  }
  ok(out.reduce((a,b)=>a+b,0)===N*N,'Parseval');return out;
}
const fixtures=[];
for(const n of [4,5,6,7,8]){
  const N=1<<n,s=(1<<(n-2))|1,flip=1<<(n-1);
  const F=Array.from({length:N},(_,x)=>Math.min(x,x^s));
  const G=Array.from({length:3},(_,j)=>F.map((v,x)=>x%3===j?v^flip:v));
  for(let x=0;x<N;x++){
    const vals=G.map(a=>a[x]);
    ok(vals.filter(v=>v===F[x]).length>=2,'majority clean');
  }
  const rows=[];
  for(let j=0;j<3;j++){
    const spec=spectrum(G[j],n);
    const bad=spec.reduce((a,v,y)=>a+(parity(y&s)?v:0),0);
    const mismatch=G[j].reduce((a,v,x)=>a+(v!==G[j][x^s]?1:0),0);
    ok(2*bad===N*mismatch,'exact wrong-equation identity');
    ok(mismatch>0,'non-exact individual period');
    rows.push({j,modified:G[j].filter((v,x)=>v!==F[x]).length,
               wrongEquationNumerator:bad,denominator:N*N});
  }
  const H=F.map((_,x)=>{
    const a=G.map(g=>g[x]);return a.find(v=>a.filter(t=>t===v).length>=2);
  });
  ok(H.every((v,x)=>v===F[x]),'pointwise identical to F');
  const spec=spectrum(H,n);
  for(let y=0;y<N;y++)ok(spec[y]===(parity(y&s)?0:2*N),'exact Fourier');
  fixtures.push({n,period:s,copies:3,views:rows,exactRecovery:true});
}
console.log(JSON.stringify({run:435,model:'aligned three-capsule complementary faults',
  assertions:checks,fixtures,positiveQPTSecurity:false,practicalWKEM:false},null,2));
