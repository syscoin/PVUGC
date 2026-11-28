# R129 — bounded heavy-tail ORIGINAL source with exact complete-public posterior (REJECTED)

**Status:** No secure ORIGINAL-witness construction advance; no ordinary top-level PR comment/user-facing update under the user's quiet-reporting rule. This is a negative research record, not a new security assumption or optimization.

**Continuity/provenance:** syscoin/PVUGC#1, open/draft/unmerged on research/pq-wkem-validation-20260918 at initial SHA dfd759cbe0f0044cd6c7f525c79ee2b161c0b523. The latest ordinary comments through 6698876958, exact R122A blob 485e44feca72d07f1c2a4fe1ace04de525b811f3, R124, R127 blob 274601b846df3bc9de44aa48d480820cf80ed01f and R128 blob 24c44d95c2cad5f70b68d1d1b11504dbfc806c3d were inspected. Only the specific research files were read; no entire PR diff or external literature/internet research.

## One explicit ORIGINAL-dependent source candidate

Continue R124's fixed FALSE original-3CNF source, (X∨X∨X) AND (not X∨not X∨not X), but change its *actual* finite independent error distribution. This is not a new iO/WE/WPRF assumption. Use:

A = [[1,1,0,0,0,0,0,0],[0,0,1,1,1,0,0,0],[0,0,0,0,0,1,1,1],[0,3,0,1,2,0,0,0],[3,0,0,0,0,0,1,2]]
b = [1,1,1,3,3]
z* = [0,1,1,0,0,0,-1,2]
N = [[0,0,3,-6,3,0,0,0],[-1,1,3,-3,0,-3,3],[-2,2,6,-6,0,-3,0,3]].

These obey A z*=b and N A^T=0, while no ORIGINAL Boolean witness exists. A^T has full column rank over the primes used. Choose B uniform in {0,1}; sample alpha uniformly conditioned on b^T alpha = B Delta mod q, which is classical PPT since a coefficient of b is 1, and sample each e_j independently. Publish *the entire* p=A^T alpha+e mod q, original relation and statement, plus any derived public data. Baseline: q=17, Delta=8, e uniform {-1,0,1}. Tested finite-tail variant: q=31, Delta=15, P(e=-2,-1,0,1,2)=(2,5,10,5,2)/24. This is a finite rational law, NOT an unbounded Cauchy or an independently justified PQ assumption.

For the analogous satisfiable one-variable two-clause relation (change the contradictory final clause), each genuine Boolean witness has onehot representation with exactly three nonzero entries. Honest Open computes z_w^T p and nearest-center-decodes B, with |z_w^T e|<=3H < min(Delta,q-Delta)/2 for the two cases H=1,2. All supported honest tapes recover the SAME B, and separate source shares could in principle feed a common signature pad. This establishes only toy source correctness, not a functioning secure generic NP compiler.

## Exact complete-public posterior, not a marginal-only check

The public distribution is correlated: the actual entire p, its syndrome Np, and z*^T p are all available to arbitrary QPT attackers. For each syndrome s and residue c, define F_s(c) as the sum of *integer weights* of all e in the specified finite support such that N e=s and z*^T e=c modulo q. Because A^T is injective, for fixed p,e there is at most one alpha and it lies in the required b^T alpha=B Delta plane exactly when z*^T e = z*^T p - B Delta mod q. Therefore the exact complete-source probability law is:

Pr[p | B] = q^(-4) F_{Np}(z*^T p - B Delta) / (sum_e weight(e)).

The statistic (Np,z*^T p) is sufficient for the full p under this source. Equal-prior optimal Bayes error for B is overlap/(2W), where W=(sum one-coordinate weights)^8 and overlap=sum_{s,v} min(F_s(v),F_s(v-Delta)). This is a direct finite probability identity; the toy source marginal can be distinguished by coherent QPT attackers at least as well as by classical MAP. Additional checking keys, contexts, auxiliaries, selective openings and related capsules are NOT simulated by this calculation and cannot be assumed harmless.

Exact enumeration gave:

- Baseline q17: 6,561 source-error tapes, 945 syndromes, W=6,561, full-public overlap=0 and optimal public bit-error=0, although projection-only MAP error is ~0.04320987654. This source publicly reveals B with certainty in the fixed FALSE toy.
- Finite-tail q31: 390,625 source-error tapes, 7,039 syndromes, W=110,075,314,176, full-public overlap=147,456, optimal public bit-error 147456/(2*110075314176) = 0.00000066979595336, versus projection-only MAP error ~0.00344208140. One-gadget overlap does not establish generic false security; the full public view sharply improves the attack.

## Padded-FALSE reduction defeats any bounded-support variant under deterministic every-witness correctness

For t disjoint contradictory blocks, publicly concatenate the invalid integer representation z*_t. It obeys A_t z*_t=b_t and ||z*_t||_2^2=7t. An honest true onehot would have L1 norm 3t. If each source coordinate error is *independently, symmetrically* supported in [-E,E], then selecting q>4E(3t)+5 yields deterministic correctness for all honest onehot paths but a classical public false opener. Indeed z*_t^T p=B Delta+Y, where Y=sum_j z*_t,j e_j and Hoeffding gives:

Pr[publicly decoding the wrong B] <= 2 exp(-(E*3t)^2/(2E^2*7t)) = 2 exp(-9t/14).

At t=512 and L<=2^20 independently generated pad bits, Pr[any public false opener wrong] < 2^-453.85. This holds for the finite-tail variant as well; the single-gadget positive overlap vanishes asymptotically under the deterministic correctness scaling. It does NOT establish a general WE impossibility, and does NOT analyze different models with stochastic correctness or deliberately unbounded/correlated noise.

## Security assessment and next indispensable equation

**REJECTED. No positive ORIGINAL source/compiler or arbitrary hard-TRUE security advance.** The toy exact law does not provide an LWE challenge simulator for the full public CK/J/Aux/context, multiple capsules or allowed selective openings, and certainly not unauthorized native-signature recovery -> ORIGINAL witness or independent QPT break. This is not a QPT security measurement or a 128-bit calibration; no LWE assumption was broken. The next candidate needs an actual nonlinear cryptographically protected discriminator with *jointly instantiable setup and opening*, not another bounded affine-noise perturbation, a public algebraic/PSD validity check, or source bits whose already-leaked values are merely hashed/XORed.

One honest N-of-N preauthorization signer, abort/erasure/DA, source SYS/BTC AuxPoW and fork semantics, graph composition and hypothetical Bitcoin native PQ path remain separate unresolved obligations; no code or endpoint was deployed.

## Exact executed V8 checker
~~~javascript
function r129ExactFullPublic(){
 const N=[[0,0,3,-6,3,0,0,0],[-1,1,3,-3,0,-3,3],[-2,2,6,-6,0,-3,0,3]], z=[0,1,1,0,0,0,-1,2];
 const results=[];const mod=(v,q)=>(v%q+q)%q;
 for(const [q,Delta,H,weights] of [[17,8,1,[1,1,1]],[31,15,2,[2,5,10,5,2]]]){
   const m=2*H+1,total=m**8,byS=new Map(),byC=Array(q).fill(0);
   for(let t=0;t<total;t++){
     let v=t,w=1,e=[];
     for(let j=0;j<8;j++){const k=v%m;v=Math.floor(v/m);e.push(k-H);w*=weights[k]}
     const s=N.map(row=>mod(row.reduce((a,b,j)=>a+b*e[j],0),q)).join(":");
     const c=mod(z.reduce((a,b,j)=>a+b*e[j],0),q);
     if(!byS.has(s))byS.set(s,new Map());
     const bucket=byS.get(s);bucket.set(c,(bucket.get(c)||0)+w);byC[c]+=w;
   }
   let overlap=0,rawOverlap=0;
   for(const bucket of byS.values())for(const [c,w] of bucket)overlap+=Math.min(w,bucket.get(mod(c-Delta,q))||0);
   for(let c=0;c<q;c++)rawOverlap+=Math.min(byC[c],byC[mod(c-Delta,q)]);
   const mass=weights.reduce((a,b)=>a+b,0)**8;
   if(!(overlap<=rawOverlap&&rawOverlap<=mass))throw Error("overlap assertion");
   if(!(3*H<Math.min(Delta,q-Delta)/2))throw Error("honest correctness bound");
   results.push({q,Delta,H,error_tapes:total,syndrome_classes:byS.size,total_weight:mass,full_public_overlap:overlap,full_public_map_error:overlap/(2*mass),projection_only_map_error:rawOverlap/(2*mass)});
 }
 if(results[0].full_public_overlap!==0 || results[1].full_public_overlap!==147456)throw Error("exact reference result mismatch");
 return {run:"R129-HEAVYTAIL-EXACT-FULL-PUBLIC-20261107",results,status:"REJECTED: only one FALSE gadget overlap; padded FALSE public attack succeeds; no generic WKEM"};
}
console.log(JSON.stringify(r129ExactFullPublic(),null,2));
~~~

## Captured output (from the actual V8 run)
~~~json
{
  "run": "R129-HEAVYTAIL-EXACT-FULL-PUBLIC-20261107",
  "results": [
    {
      "q": 17,
      "Delta": 8,
      "H": 1,
      "error_tapes": 6561,
      "syndrome_classes": 945,
      "total_weight": 6561,
      "full_public_overlap": 0,
      "full_public_map_error": 0,
      "projection_only_map_error": 0.043209876543209874
    },
    {
      "q": 31,
      "Delta": 15,
      "H": 2,
      "error_tapes": 390625,
      "syndrome_classes": 7039,
      "total_weight": 110075314176,
      "full_public_overlap": 147456,
      "full_public_map_error": 6.697959533607681e-7,
      "projection_only_map_error": 0.0034420814043209878
    }
  ],
  "status": "REJECTED: only one FALSE gadget overlap; padded FALSE public attack succeeds; no generic WKEM"
}
~~~

An independent offline CPython standard-library enumerator was also executed and agreed on all finite overlap values; that local-only checker is not falsely described as committed. Local checker SHA256 c971b65e10483c246e784f50fb4d606b39216fba714d8c163fc6f897adfb36ae, local output SHA256 070055b62070387d6eeed96088879322311f950d8dbb8d588061400e81f2857e. Publication of this file, if completed, is only an exact research checkpoint; no ordinary PR progress comment is justified.
