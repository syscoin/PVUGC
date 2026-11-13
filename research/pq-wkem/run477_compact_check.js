'use strict';
// Run 477: exact finite binary-ISIS census. Toy fields; no cryptographic hardness test.
const assert = require('node:assert/strict');
let checks = 0;
function ok(x) { assert.ok(x); checks++; }
function test(q, m) {
  const matrices = q ** m, N = 2 ** m;
  let missing = 0, support = 0, total = 0, squares = 0, plantedMatch = 0;
  for (let code = 0; code < matrices; code++) {
    let v = code;
    const a = Array.from({length:m}, () => { const r=v%q; v=Math.floor(v/q); return r; });
    const fibers = Array.from({length:q}, () => []);
    for (let w=0; w<N; w++) {
      let b=0;
      for (let j=0; j<m; j++) b += a[j] * ((w>>j)&1);
      fibers[b%q].push(w);
    }
    ok(fibers.reduce((n,f)=>n+f.length,0) === N);
    for (let b=0; b<q; b++) {
      const f=fibers[b], z=f.length;
      total+=z; squares+=z*z;
      if (!z) {missing++; continue;}
      support++;
      const w=f[0];
      for (const t of f) {
        if (w===t) {plantedMatch++; continue;}
        let sum=0, nonzero=false;
        for (let j=0; j<m; j++) {
          const d=((w>>j)&1)-((t>>j)&1);
          ok(d>=-1 && d<=1);
          if (d!==0) nonzero=true;
          sum+=a[j]*d;
        }
        ok(nonzero && ((sum%q)+q)%q===0);
      }
    }
  }
  ok(total===matrices*N);
  ok(squares*q===matrices*(N*N+N*(q-1)));
  ok(plantedMatch===support);
  ok(missing+support===matrices*q);
  ok(missing*(N+q-1)<=matrices*q*(q-1));
  ok(support<=matrices*q);
  return {q,n:1,m,matrices,targets:matrices*q,missing,
          missing_fraction:String(missing)+'/'+String(matrices*q),
          planted_match_fraction:String(plantedMatch)+'/'+String(matrices*N)};
}
const cases = [[5,2],[5,3],[5,4],[7,3]].map(([q,m])=>test(q,m));
console.log(JSON.stringify({run:477,status:'PASS',checks,cases,
  scope:'finite exact binary-syndrome census only; SIS QPT hardness untested'},null,2));
