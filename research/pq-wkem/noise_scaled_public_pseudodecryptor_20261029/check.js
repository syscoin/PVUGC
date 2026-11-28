"use strict";
// Exact offline finite checks for the paired-binary noise scaling and uniform-source density lemmas.
// No network, cryptographic signatures, QPT tests, or external libraries.
const assert = require("node:assert/strict");
let checks = 0;
function ok(condition, why) { assert.ok(condition, why); ++checks; }
const q = 7, m = 3, h = 2;
const sphere = [];
for (let a = -h; a <= h; ++a)
  for (let b = -h; b <= h; ++b)
    for (let c = -h; c <= h; ++c)
      if (Math.abs(a)+Math.abs(b)+Math.abs(c) === h) sphere.push([a,b,c]);
ok(sphere.length === 18, "sphere size");
let occupied = 0, moment1 = 0, moment2 = 0;
for (let a = 0; a < q; ++a) for (let b = 0; b < q; ++b)
  for (let c = 0; c < q; ++c) {
    const cells = Array(q).fill(0);
    for (const w of sphere) {
      const val = ((a*w[0]+b*w[1]+c*w[2])%q+q)%q;
      cells[val]++;
    }
    for (const x of cells) {
      occupied += Number(x>0); moment1+=x; moment2+=x*x;
    }
  }
const total = q ** 4, Nsrc = sphere.length;
ok(moment1*q === Nsrc*total, "first moment");
ok(moment2*q*q === (Nsrc*q + Nsrc*(Nsrc-1))*total, "second moment");
ok(occupied/total >= Nsrc/(Nsrc+q-1), "source-density lower bound");
const settings = [];
for (const B of [1,8,128,1024]) {
  const N=160, f=32, g=2*B*(N+1)+1, Q=1000003, T=Math.floor(Q/g);
  ok(T>=2, "valid digit radix");
  let power=1, ell=0; while (power < 2**256) { power*=T; ++ell; }
  const L=3*ell, norm2=N+4*f;
  const exponent=(g/2)**2 / (2*B*B*(1+norm2));
  const log2Fail=Math.log2(2*L)-exponent/Math.log(2);
  ok(norm2===288 && log2Fail< -50, "false pseudo-decryptor remains reliable");
  settings.push({B,g,T,L,log2FailureBound:Number(log2Fail.toFixed(6))});
}
const repeats=[];
for (const r of [1,2,4,8]) {
  const v=32, c=2*v*r, N=v+2*c, f=v*r, norm2=N+4*f;
  const exponent=(N+1)**2/(2*(1+norm2));
  ok(norm2===v*(1+8*r), "repetition pseudo opening norm");
  repeats.push({r,N,f,norm2,exponent:Number(exponent.toFixed(4))});
}
const result={status:"PASS",checks,uniformSource:{q,m,h,N:Nsrc,
  observedOccupied:`${occupied}/${total}`,soundFalseTVLowerBound:`${Nsrc}/${Nsrc+q-1}`},
  boundedNoise:settings,replication:repeats,
  scope:"exact classical identities and Hoeffding parameters; not a secure WKEM"};
console.log(JSON.stringify(result,null,2));
