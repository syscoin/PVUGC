# R67 — Minimum-gap noise-tail repair test of the R63 ORIGINAL compiler

**Status: NO POSITIVE WITNESS-KEM ADVANCE.** Run R67-MIN-GAP-NOISE-TAIL-20261104, 2026-11-04. Offline continuity from syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, start head 43feaf27827cba0109f9e25c2da56d4ab0a85734. Exact R63 mathematical input is research/pq-wkem/r63_original_short_kernel_20261104/RESEARCH.md blob 25b55c74f1e72e94cb1a3f7e4f2f00e966696bec. The later R66 input is blob 202cb2779dc740ffad213481faa8b6f27fde1842. No external internet/literature.

## Attempted release repair

R63's linear source was C_i=A_x s_i+e_i+Delta mu_i e0 mod q. Matrix A_x is deterministically constructed from arbitrary 3CNF x, not uniformly sampled. Each s_i is uniform over Z_q^n; error coordinates are **independent, mean zero and bounded by E**. Every genuine ORIGINAL witness maps to binary r with r0=1, A_x^T r=0, and ||r||_1=N=1+v+c, so r^T C_i=Delta mu_i+r^T e_i. Exact all-witness decoding for any allowed error requires Delta>2NE, plus a sufficiently large circular-codeword gap in q.

R63 already showed that a publicly constructed signed h from an arbitrary assignment w, with u unsatisfied clauses, defeats the source deterministically when Delta>2(N+2u)E. This iteration tests the concrete repair Delta=2NE+1, which **fails** the old attack's worst-case premise but preserves all genuine ORIGINAL-witness correctness.

## New exact argument

For EVERY assignment w, including any trivial choice on FALSE x, its R63 signed clause slack (0,-1,2) gives publicly computable h with h0=1, A_x^T h=0, ||h||_1=N+2u and ||h||_2^2=N+4u. Public evaluation therefore yields y_i=h^T C_i=Delta mu_i+Z_i, Z_i=sum_j h_j e_ij, modulo q.

Independence, mean zero and bounded support of actual source errors imply, by Hoeffding:

    Pr[|Z_i| >= Delta/2] <= 2 exp(-Delta^2/(8 E^2 (N+4u)))
                               < 2 exp(-N^2/(2(N+4u)))
                               <= 2 exp(-N/10), because u<=c<=N.

A circular nearest-center decoder succeeds whenever |Z_i|<Delta/2 and q keeps the 0/Delta codewords separated. For k encrypted bits, the union bound shows full public recovery failure at most 2k exp(-N/10). This is a classical direct decoding algorithm requiring **no actual ORIGINAL witness** or adversary-volunteered internal representation. It applies on FALSE inputs and does not assume any x-structured LWE hardness. Adding public CK, Aux, context, related capsules, or a masked native signature cannot restore a root already recovered from C. On arbitrarily large FALSE instances padded with tautologies, the failure becomes negligible as N grows. Thus narrowing Delta alone is NOT a secure repair.

The bound is for R63's **unrounded independent bounded centered errors**. It is not a theorem about R66 rounding correlations, other correlated-noise sources, or genuinely nonlinear witness gates. This iteration produced no secure new source. A new scheme must replace publicly linear recovery and instantiate its genuine statement-dependent joint-public-output QPT simulator before any recovery-to-ORIGINAL-witness claim.

## Reproducible checks and provenance

The exact compact checker below was executed in connected V8 before publication. It uses the known R63 h coefficient pattern for the FALSE fixture of 128 copies each of z and NOT z, N=258, u=128, q=8192, E=1, Delta=517, h-l1=514, h-l2-squared=770, and recovers all 256 illustrative bits; the Hoeffding union bound is about 7.32e-17. Its tiny exact enumeration of independent chi=uniform{-1,0,1} on FALSE z AND NOT z gives 5/243 erroneous decodes per bit at Delta=9. This checker uses a deterministic toy generator and tests the signed-noise identity, not cryptographic strength.

A separate extended LOCAL-ONLY Node.js checker (not byte-identical to this published checker) verified the actual 513 sparse R63 kernel equations, formed full ciphertexts A_x s+e+Delta mu e0, recovered all 256 bits, and reconstructed a scoped SHA256/HMAC checking key, auxiliary data, related-capsule Base and 96-byte **synthetic** masked signature. It passed 1,035 assertions. Neither checker instantiates QPT-secure LWE or native PQ signatures.

The FULL remaining requirement is an independently justified classical-PPT setup/opening source and whole-public-view QPT challenge simulation, with arbitrary unauthorized hard-TRUE final capability recovery/native forgery yielding an **ACTUAL ORIGINAL witness** or independent PQ break. Arbitrary FALSE security, malicious N-of-N setup/abort and conditional Bitcoin endpoint are also missing. Research only; do not mark complete.

## Exact executed compact checker

```javascript
'use strict';
// Exact compact R67 checker, synthetic source, NO QPT evidence.
let count=0;function test(x){count++;if(!x)throw Error('failed '+count)}
const N=258,u=128,E=1,D=2*N*E+1,q=8192,k=256;
const h=[1,1];for(let i=0;i<256;i++)if(i%2===0)h.push(1);else h.push(-1,2);
const l1=h.reduce((s,x)=>s+Math.abs(x),0),l2=h.reduce((s,x)=>s+x*x,0);
test(l1===N+2*u&&l2===N+4*u&&D===517&&l1>D/2);
let seed=0x9e3779b9;function rnd(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0}
const mod=(z,p)=>((z%p)+p)%p;let max=0;
for(let i=0;i<k;i++){
 const bit=rnd()%2,secretNoise=h.reduce((sum,a)=>sum+a*((rnd()%3)-1),0);
 const observed=mod(D*bit+secretNoise,q);
 const d0=Math.min(observed,q-observed);
 const d1=Math.min(mod(observed-D,q),mod(D-observed,q));
 test(Number(d1<d0)===bit);max=Math.max(max,Math.abs(secretNoise));
}
let bad0=0,bad1=0,total=0;
const small=[1,1,1,-1,2];
function rec(i,z){if(i===5){total++;for(let bit=0;bit<2;bit++){
 const y=mod(9*bit+z,128),d0=Math.min(y,128-y),d1=Math.min(mod(y-9,128),mod(9-y,128));
 if(Number(d1<d0)!==bit){if(bit)bad1++;else bad0++}}return;}
 for(let e=-1;e<=1;e++)rec(i+1,z+e*small[i]);}
rec(0,0);test(total===243&&bad0===5&&bad1===5);
const tail=2*Math.exp(-D*D/(8*l2));
const result={run:'R67-MIN-GAP-NOISE-TAIL-20261104',status:'NO_POSITIVE_WKEM_ADVANCE',
 N,u,Delta:D,q,l1,l2,recovered_bits:k,max_abs_noise:max,
 bound_per_bit:tail,union_bound_256:tail*k,small_false_exact_error:'5/243',assertions:count,
 scope:'source-noise lemma only; complete A_x and HMAC checks in separately executed local checker'};
if(typeof console!=='undefined'&&console.log)console.log(JSON.stringify(result,null,2));
```

## Exact captured output

```json
{
  "run": "R67-MIN-GAP-NOISE-TAIL-20261104",
  "status": "NO_POSITIVE_WKEM_ADVANCE",
  "N": 258,
  "u": 128,
  "Delta": 517,
  "q": 8192,
  "l1": 514,
  "l2": 770,
  "recovered_bits": 256,
  "max_abs_noise": 63,
  "bound_per_bit": 2.861060953703304e-19,
  "union_bound_256": 7.324316041480458e-17,
  "small_false_exact_error": "5/243",
  "assertions": 258,
  "scope": "source-noise lemma only; complete A_x and HMAC checks in separately executed local checker"
}
```
