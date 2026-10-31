const report=(()=>{
 const q=101,K=17;let assertions=0,success=0,misses=0;
 const ok=(p,m)=>{if(!p)throw Error(m);++assertions},mod=x=>(x%q+q)%q;
 const pow=(a,b)=>{let v=1;while(b){if(b%2)v=mod(v*a);a=mod(a*a);b=Math.floor(b/2)}return v};
 const mv=(A,v)=>A.map(r=>mod(r.reduce((s,a,i)=>s+a*v[i],0)));
 const dot=(u,v)=>mod(u.reduce((s,x,i)=>s+x*v[i],0));
 const trim=a=>{a=a.slice().map(mod);while(a.length>1&&!a[a.length-1])a.pop();return a};
 const mul=(a,b)=>{let c=Array(a.length+b.length-1).fill(0);for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++)c[i+j]=mod(c[i+j]+a[i]*b[j]);return trim(c)};
 const rem=(a,b)=>{a=trim(a);b=trim(b);if(b.length===1&&b[0]===0)throw Error('zero modulus');
    while(a.length>=b.length&&!(a.length===1&&a[0]===0)){let coef=mod(a[a.length-1]*pow(b[b.length-1],q-2)),d=a.length-b.length;for(let j=0;j<b.length;j++)a[j+d]=mod(a[j+d]-coef*b[j]);a=trim(a)}
    return a};
 const powmod=(a,k,f)=>{let v=[1];a=rem(a,f);while(k){if(k%2)v=rem(mul(v,a),f);a=rem(mul(a,a),f);k=Math.floor(k/2)}return v};
 const gcd=(a,b)=>{while(!(b.length===1&&b[0]===0)){let c=rem(a,b);a=b;b=c}let inv=pow(a[a.length-1],q-2);return a.map(x=>mod(x*inv))};
 const fieldPart=desc=>{let f=desc.slice().reverse();if(f.length===1)return [1];let r=powmod([0,1],q,f);while(r.length<2)r.push(0);r[1]=mod(r[1]-1);return gcd(f,rem(r,f))};
 const evalDesc=(f,t)=>f.reduce((a,c)=>mod(a*t+c),0);
 const bm=seq=>{let C=[1],B=[1],L=0,step=1,b=1;
   for(let n=0;n<seq.length;n++){let d=mod(seq[n]+Array.from({length:L},(_,i)=>C[i+1]*seq[n-i-1]).reduce((a,b)=>a+b,0));
    if(!d){step++;continue}let T=C.slice(),co=mod(d*pow(b,q-2));
    while(C.length<B.length+step)C.push(0);
    for(let j=0;j<B.length;j++)C[j+step]=mod(C[j+step]-co*B[j]);
    if(2*L<=n){L=n+1-L;B=T;b=d;step=1}else step++;
   }return C.slice(0,L+1)};
 const recurrence=(A,u,v)=>{let s=[],p=v.slice();for(let i=0;i<2*A.length;i++){s.push(dot(u,p));if(i+1<2*A.length)p=mv(A,p)}return bm(s)};
 let state=0x6a09e667;const rnd=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return (state>>>0)%q};
 for(let t of [0,1]){
  const A=[[mod(K+t),0,0],[0,mod(K+1-t),0],[0,0,K+1]];
  ok(evalDesc(fieldPart(recurrence(A,[1,1,1],[1,1,1])).slice().reverse(),K)===0,'deterministic recovery');
  for(let trial=0;trial<20;trial++){
   let found=false;for(let attempt=0;attempt<5;attempt++){
    let u=Array.from({length:3},rnd),v=Array.from({length:3},rnd),p=fieldPart(recurrence(A,u,v));
    if(evalDesc(p.slice().reverse(),K)===0){found=true;success++;break}else misses++;
   }
   ok(found,'same K under fresh projection');
  }
 }
 const nonsplit=fieldPart([1,84,2,67]); // (T-17)(T^2+2) over F101
 ok(JSON.stringify(nonsplit)===JSON.stringify([84,1]),'irreducible quadratic removed by Frobenius gcd');
 let J=[[K,1,0],[0,K,0],[0,0,K+5]];
 ok(evalDesc(recurrence(J,[0,0,1],[1,1,1]),K)!==0,'fixed bad projection omits K');
 let repaired=false;for(let i=0;i<8;i++){
  const u=Array.from({length:3},rnd),v=Array.from({length:3},rnd);
  if(evalDesc(fieldPart(recurrence(J,u,v)).slice().reverse(),K)===0){repaired=true;break}
 }
 ok(repaired,'fresh projection recovers defective K-eigenspace');
 ok(evalDesc(fieldPart(recurrence([[0,1],[0,0]],[1,1],[1,1])).slice().reverse(),0)===0,'zero K-primary');
 return {run:696,algorithm:'Krylov/Berlekamp-Massey plus Frobenius field-root isolation',field:q,valid_witness_classes:2,successful_cases:success,retried_misses:misses,nonlinear_factors_discarded:true,assertions_passed:assertions,status:'algebra/correctness only; no QPT hiding/extraction'};
})();
