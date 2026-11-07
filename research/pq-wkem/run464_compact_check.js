'use strict';
let checks = 0;
function ok(b) { checks++; if (!b) throw Error('check ' + checks); }
function parity(x) { let p = 0; while (x) { p ^= 1; x &= x - 1; } return p; }
function perms(a) { if (!a.length) return [[]]; const out=[]; for(let i=0;i<a.length;i++) for(const t of perms(a.filter((_,j)=>j!==i)))out.push([a[i],...t]); return out; }
const ps=perms([0,1,2,3]); let oraclePairs=0;
const baseline=new Set();
for(let d=0;d<4;d++) {
  const pairs=new Set();
  for(const p of ps) for(const l of ps) {
    const f=Array.from({length:4},(_,z)=>l[p[z^d]]);
    const key=p.join('')+'|'+f.join(''); ok(!pairs.has(key)); pairs.add(key);
  }
  ok(pairs.size===576);
  if(d===0) for(const k of pairs) baseline.add(k);
  else for(const k of pairs)ok(baseline.has(k));
  oraclePairs+=pairs.size;
}
let fixtures=0;
for(const n of [3,4,5]) {
  const N=1<<n, d=(1<<(n-1))-1;
  const p=z=>(5*z+3)%N, l=z=>(z+1)%N;
  const f0=z=>p(z), f1=z=>l(p(z^d)), h=z=>l(f0(z));
  for(let z=0;z<N;z++){ok(f1(z)===h(z^d));ok(f0(z)!==f1(z^d));}
  function bias(adjusted) {
    const g0=adjusted?h:f0;
    const a0=Array.from({length:N},(_,y)=>Array.from({length:N},(_,z)=>z).find(z=>g0(z)===y));
    const a1=Array.from({length:N},(_,y)=>Array.from({length:N},(_,z)=>z).find(z=>f1(z)===y));
    let sum=0;
    for(let y=0;y<2*N;y++) {
      let weight=0;
      for(let out=0;out<N;out++) {
        const a=(parity(a0[out]&y)?-1:1)+(parity((N+a1[out])&y)?-1:1);
        weight+=a*a;
      }
      const prob=weight/(4*N*N);
      const expected=adjusted?(parity(y&(N|d))===0?1/N:0):null;
      if(adjusted)ok(Math.abs(prob-expected)<1e-12);
      sum+=(parity(y&(N|d))?-1:1)*prob;
    }
    return sum;
  }
  ok(Math.abs(bias(false))<1e-12);ok(Math.abs(bias(true)-1)<1e-12);
  fixtures++;
}
console.log(JSON.stringify({run:464,assertions:checks,oracle_distribution_pairs:oraclePairs,forward_label_fixtures:fixtures,success:true}));
