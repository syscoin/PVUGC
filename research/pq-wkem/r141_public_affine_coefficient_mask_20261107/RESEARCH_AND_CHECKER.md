# R141 — Exact public-affine source-mask dichotomy (rejected, not generic WKEM)

**Status: structural negative; NO secure ORIGINAL-dependent witness-KEM, NO positive advance meeting the user-facing threshold.** This is a single bounded offline iteration, not an efficiency optimization. It continues the R140 exponential full Boolean-quotient table control, with exact R140 predecessor blob `ef483ec7cc246598b451014cff6877d0f0df93f0`. The predecessor's full independent private per-assignment masks give correct every-witness common release and information-theoretic fixed-FALSE hiding but exponential classical-PPT/size failure.

## Candidate release, genuinely using ORIGINAL x

Let ORIGINAL relation `R(x,w)=1` be represented exactly on Boolean `w in {0,1}^n` by public polynomial-time constraints `C_j(x,w)=0`. Bind x to relation, claim/UTXO, branch, anchors/window, context and intended native verification key/capability.

In `B_n=F_q[z_1,...,z_n]/(z_i^2-z_i)`, let `V_D=span{z_S: |S|<=D}`, `N_D=sum_{i=0}^D binom(n,i)`, and `I_D=span{C_j(x,z) z_S (Boolean-reduced): degree<=D}`. For scalar precommitted capability k, sample each coefficient a_(j,S) uniformly and independently in F_q, publish **only the expanded coefficients** of the polynomial

`P_D(z)=k + sum_(j,S admissible) a_(j,S) C_j(x,z) z_S`.

Never publish k, raw a_(j,S), a public code literal containing them, or independent secret-dependent receipts. Any ORIGINAL valid w evaluates `P_D(w)=k` identically for EVERY witness and on EVERY builder randomness tape. For fixed D and bounded-degree constraints, honest classical Build/Open and the public coefficient array are polynomial-size. Evaluation is off chain. This step is an actual algorithm but its security is completely defeated as shown next; no native signature, VKey, CK/J/Aux or multi-capsule composition is established.

## Exhaustive algebraic proof: publicly known affine mask spans cannot work

Generalize to any public source `P=k*u+M*r in F_q^N`, with publicly computable vector u and matrix M, and independently uniform r. The public representation is a vector of its ACTUAL coefficients, not opaque encryption or obfuscation.

* If `u in im(M)`, `M*r` is exactly uniform on `im(M)`, so the full public **P alone** is identically distributed for all k, even to unbounded/quantum distinguishers. Secret-correlated VK, CK, J, Aux and sibling capsules require independent analysis and do not inherit this result automatically.
* If `u notin im(M)`, ordinary public Gaussian elimination produces `ell` with `ell*u=1` and `ell*M=0`. The algorithm `ell*P` deterministically recovers **k for every tape without an ORIGINAL witness** in polynomial time in N and the number of public columns. No SourceOpen oracle, adversary-supplied representation, quantum computation, or LWE challenge secret is needed.

These are exhaustive mutually exclusive cases for any x. In the Boolean construction u is the constant 1 and im(M)=I_D. Whenever ORIGINAL x is TRUE, a real satisfying witness w defines an evaluation functional annihilating I_D and taking 1 to 1. Therefore necessarily `1 notin I_D`, and the public `ell` attack exists on **EVERY TRUE x**, including hard-TRUE instances in the intended security game. The adversary computes k from public coefficients, without obtaining w. The algorithm provides no way to reduce arbitrary native forgery/capability recovery to the ORIGINAL witness unless witness finding is already easy or a separate justified PQ break arises. For FALSE x, `1 in I_D` gives exact source-coordinate hiding and `1 notin I_D` gives exact public key recovery. This covers any public polynomial-dimensional affine coefficient mask, not only degree-three moments. It does not rule out opaque nonlinear public encodings or LWE constructions outside this public-affine class.

## Exact finite check (q=7)

Using the original K4 parity-to-3CNF reference with six Boolean edge variables and four degree-three vertex parity mismatch polynomials: odd total charge `b=(1,0,0,0)` is FALSE, uncharged b=0 is TRUE with eight valid ORIGINAL witnesses. An independently executed local standard-library Python checker generated exact multilinear constraint coefficients via Möbius inversion, expanded all allowed mask multiples in B_6, calculated rank and the unit-in-span relation, constructed ell for each unhidden case and checked direct public k recovery on all seven field keys. Ranks:

| Statement | D | N_D | rank I_D | 1 in I_D | Public key extractor |
|---|---:|---:|---:|---|---|
| K4 FALSE | 3 | 42 | 16 | no | yes |
| K4 FALSE | 4 | 57 | 53 | no | yes |
| K4 FALSE | 5 | 63 | 63 | yes | no; P alone uniform |
| K4 FALSE | 6 | 64 | 64 | yes | no; P alone uniform |
| K4 TRUE | 3 | 42 | 16 | no | yes |
| K4 TRUE | 4 | 57 | 46 | no | yes |
| K4 TRUE | 5 | 63 | 55 | no | yes |
| K4 TRUE | 6 | 64 | 56 | no | yes |
| z AND (NOT z), FALSE | 1 | 2 | 2 | yes | no; P alone uniform |

Independent **local-only** Python checker: `checker.py` SHA-256 `3e4eb20374e15555805feecf8bd00372a6c95dca049791e88f105dd78179713c`; local captured JSON SHA-256 `d0d106133b9bed61cfbeedba4b3cb5e5db344867612beec9779935f4056fed6c`; **1334 assertions passed**. These are actual local files but are NOT GitHub-published. No claim that the finite assertions prove QPT security.

## Exact published V8 checker

The following is the complete source of the function actually executed in this GitHub-connected V8 runtime, whose output follows. It exhaustively verifies the full F7^2 false-law histogram for unsatisfiable z AND NOT z, the TRUE public dual extractor, every-valid-witness same-capability correctness for OR(z1,z2), and simultaneous public key recovery without presenting w. Its assertions are not cryptographic security experiments.

```javascript
function boundedCheckR141() {
 "use strict";
 const q=7; let assertions=0;
 const mod=x=>(x%q+q)%q;
 const ok=(v,description)=>{assertions++;if(!v)throw Error("assertion "+assertions+": "+description);};
 function solve(M,b) {
   const a=M.map((row,i)=>[...row.map(mod),mod(b[i])]);
   const n=M[0].length; let rank=0; const piv=[];
   for(let col=0;col<n;col++) {
     let p=rank;while(p<a.length && a[p][col]===0)p++;
     if(p===a.length)continue;
     [a[p],a[rank]]=[a[rank],a[p]];
     let inv=1;while(mod(inv*a[rank][col])!==1)inv++;
     a[rank]=a[rank].map(v=>mod(v*inv));
     for(let r=0;r<a.length;r++)if(r!==rank){
       const t=a[r][col];
       if(t)a[r]=a[r].map((v,j)=>mod(v-t*a[rank][j]));
     }
     piv.push(col);rank++;
   }
   for(let r=rank;r<a.length;r++)if(a[r][n])return null;
   const x=Array(n).fill(0);
   for(let i=0;i<rank;i++)x[piv[i]]=a[i][n];
   ok(M.every((row,i)=>mod(row.reduce((s,v,j)=>s+v*x[j],0))===mod(b[i])),"exact linear solve");
   return x;
 }
 const u=[1,0];
 const Fcols=[[0,1],[1,6]];
 const Tcols=[[6,1]];
 const f=solve([...Fcols,u],[0,0,1]);
 const t=solve([...Tcols,u],[0,1]);
 ok(f===null,"FALSE unit is inside public mask span");
 ok(t!==null,"TRUE has public dual functional");
 const histogram=[];
 for(let k=0;k<q;k++){
   const h=Array(q*q).fill(0);
   for(let a=0;a<q;a++)for(let b=0;b<q;b++){
     const P=[mod(k+b),mod(a-b)];
     h[P[0]*q+P[1]]++;
     const decodedFromPublic=mod(t[0]*mod(k-1)+t[1]*1);
     ok(decodedFromPublic===k,"TRUE public dual recovers without witness");
   }
   ok(h.every(v=>v===1),"FALSE P law exactly uniform independent of k");
   histogram.push(h.filter(v=>v!==1).length);
 }
 const C=[1,6,6,1], ell=[1,1,0,0];
 const eval2=(P,w)=>mod(P.reduce((s,v,i)=>s+(((i&1)&&!(w&1))||((i&2)&&!(w&2))?0:v),0));
 for(let k=0;k<q;k++)for(let a=0;a<q;a++){
   const P=C.map((v,i)=>mod((i===0?k:0)+a*v));
   for(let w of [1,2,3])ok(eval2(P,w)===k,"all ORIGINAL OR witnesses recover same capability");
   ok(mod(P[0]+P[1])===k,"witness-free public dual recovers same capability");
 }
 return {status:"EXACT_AFFINE_MASK_SPAN_DICHOTOMY_NOT_GENERIC_WKEM",q,assertions,unsatHistogramDeviations:histogram,unsatSpanContainsUnit:true,truePublicDual:t,trueWitnessCountForOR:3};
}
```

Captured V8 return value (reexecuted before creating Git objects):

```json
{
  "status": "EXACT_AFFINE_MASK_SPAN_DICHOTOMY_NOT_GENERIC_WKEM",
  "q": 7,
  "assertions": 549,
  "unsatHistogramDeviations": [
    0,
    0,
    0,
    0,
    0,
    0,
    0
  ],
  "unsatSpanContainsUnit": true,
  "truePublicDual": [
    1,
    1
  ],
  "trueWitnessCountForOR": 3
}
```

## Explicit exclusion and exact handoff

This is a broad NO-GO for **publicly inspectable polynomial-dimensional affine-mask coefficient releases**, not a generic impossibility theorem for witness encryption. The remaining indispensable candidate must genuinely conceal or cryptographically constrain those linear functionals in its ACTUAL public output, enforce global Boolean consistency, and jointly instantiate real statement-dependent source LWE keys, openings, and a simulator for J/CK/Aux/native VK/claim context/related capsules and selective openings. Merely adding ordinary scalar LWE pads, PRGs or publishing an obfuscated verifier by assumption does not instantiate the missing algorithm or its QPT reduction.

Actual arbitrary QPT recovery or accepted native forgery -> ORIGINAL witness or independently justified QPT break remains unproved; generic fixed-FALSE source security, malicious N-of-N ceremony/abort, graph/DA/presignature composition, parameter calibration and conditional Bitcoin-native PQ endpoints remain unsolved. No user-facing progress comment is warranted because this is a structural rejection, not a constructive security milestone. No external literature or internet research was performed.
