'use strict';
// Run 532: exact toy public-token enumeration and ideal Grover amplitude checks.
// No native SLH implementation, practical compiler, or QPT security claim.
const crypto = require('crypto');
const key = Buffer.from('run532-fixed-key');
const vk = crypto.createHash('sha256').update(key).digest('hex');
let cases = 0, recovered = 0, tokenQueries = 0, minGrover = 1;
const results = [];
for (let bits = 4; bits <= 10; bits++) {
  const n = 2 ** bits;
  for (const m of [1,2,3]) {
    const accepted = new Set(Array.from({length:m}, (_,j) => (13*j+5)%n));
    if (accepted.size !== m) throw Error('collision');
    const T = s => accepted.has(s) ? key : null;
    let calls = 0, found = false;
    for (let s=0; s<n; s++) {
      calls++;
      const candidate = T(s);
      if (candidate && crypto.createHash('sha256').update(candidate).digest('hex') === vk) {
        found = true; break;
      }
    }
    if (!found) throw Error('enumeration failed');
    const theta = Math.asin(Math.sqrt(m/n));
    const q = Math.round(Math.PI/(4*theta)-0.5);
    const success = Math.sin((2*q+1)*theta)**2;
    if (!(success>0.5)) throw Error('amplification failed');
    minGrover = Math.min(minGrover,success);
    cases++; recovered++; tokenQueries += calls;
    if (bits===4 || bits===10) results.push({bits,m,queries:calls,groverIterations:q});
  }
}
// Three distinguishable valid witness tokens release identical native capability.
const witnesses = new Map([[7,3],[11,9],[19,12]]);
const terminal = s => [...witnesses.values()].includes(s) ? key : null;
for (const s of witnesses.values()) if (!terminal(s).equals(key)) throw Error('agreement failed');
console.log(JSON.stringify({run:532,status:'PASS',cases,recovered,tokenQueries,allWitnessDistinctTokens:witnesses.size,minIdealGroverProbability:+minGrover.toFixed(10),sample:results,scope:'toy public-callable short frontier; not WKEM security or native SLH'},null,2));
