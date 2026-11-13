# R158 — Independent LWE-column injection into ORIGINAL witness phases: correctness/simulator obstruction

**STATUS: ROUTINE NEGATIVE FOUNDATION CHECK, NOT A SECURE GENERIC WKEM AND NOT A BREAKTHROUGH.** Do not publish a top-level PR progress comment or notify the user on the basis of this run. No source optimization. Exact observed prewrite PR head: \`ffce136619b6f492d30478b692157d3df71387dd\`, open/draft/unmerged, branch \`research/pq-wkem-validation-20260918\`. Latest substantive top-level comment 6718361572 (R153); immediate source continuation R157 (\`research/pq-wkem/r157_bool_ideal_noisy_phase_20261108/RESEARCH_AND_CHECKER.md\`, blob a5a5d2325ce06e836765e208ebbb86c1828a2c74). Its Boolean-ideal coefficient source is **not** ordinary random-matrix LWE, and cannot acquire a joint QPT proof merely from a marginal pad hybrid.

## Exact attempted LWE source repair and all-witness release law

We attempt to turn a statement-dependent affine ORIGINAL-source into an ordinary-LWE-looking source by independently adding uniform random LWE matrix columns. Let q be an odd prime; dimensions m,k,t be polynomial in the security parameter, and let the public ORIGINAL statement x include relation/verifier identity, claim/UTXO, branch, anchors/window, context, native VK/capability and capsule ID. Fix public G_x in F_q^(k×m) and b_x in F_q^k, such that each valid ORIGINAL witness w yields a *possibly distinct* integer z_w in F_q^m with G_x z_w=b_x. This is a **supplied-representation completeness interface only**, not an extractor from arbitrary key recovery.

The actual (unconditionally sampled) proposed public source on each key bit K in {0,1} is:
- Sample r uniform in F_q^k; R uniform in F_q^(m×t); u uniform in F_q^t, independent; genuine short e in Z^m and e0 in Z sampled from independent bounded supports then reduced modulo q.
- Publish all of x, G_x,b_x,R and c=G_x^T r+R u+e mod q, t0=b_x^T r+Delta*K+e0 mod q. Any checking data J/CK/Aux, sibling capsules, source keys, native VK and context remain in the public view; no claimed QPT full-joint simulator exists for this source.
- Naive public off-chain Open(x,w,c,t0) verifies ORIGINAL w, computes z_w from w, and tries to decode t0-z_w^T c = Delta*K+e0-z_w^T e - z_w^T R u mod q.

A valid witness does **not** know u and cannot cancel its independent random contribution. This fails even single-witness correctness in general, and distinct valid witness states expose a sharper joint obstruction.

For any two distinct valid representations z0,z1 with d=z0-z1 nonzero modulo q, the difference of their phase noises is (up to sign)
    d^T e + d^T R u.
Independently of any source key K, conditional on u ≠ 0, d^T R u is exactly uniform over F_q, because R is uniform and d ≠ 0. When u=0 it is zero. Hence
    Pr[d^T R u=0] = q^(-t) + (1-q^(-t))/q
and for **any** phase tolerance interval I of cardinality h (possibly shifted by fixed e),
    Pr[d^T R u ∈ I] ≤ q^(-t)+(1-q^(-t))*h/q.
In a narrow-phase decoding design requiring both honest residuals in [-B,B] as ordinary integers with no wrap, the difference must lie in [-2B,2B], and the probability of simultaneous correct *narrow-phase decoding* is bounded above by
    q^(-t)+(1-q^(-t))*min(q,4B+1)/q.
This is an unconditional distribution calculation, not an IND-CPA or QPT theorem. It does not claim an arbitrary wide-decoding rule obeys this bound. With genuinely random independent columns, an all-witness robust narrow-phase release cannot be inferred from ordinary QPT-LWE.

### Concrete two-witness example

Take G=[1 1], b=1, z0=(1,0), z1=(0,1), e=e0=0. If an added column R=[a;b] and u are uniform, c=(r+au,r+bu), t0=r+Delta K. The phases are Delta K-au and Delta K-bu. Their mismatch is (b-a)u. It vanishes with the exact probability 1/q+(1-1/q)/q = (2q-1)/q². Both z0 and z1 are valid ORIGINAL representations, yet a common narrow decoded bit is not generally supported by this additive independent-LWE source.

## Exact repair, and why it contributes no independent LWE hiding

If instead R=G_x^T H for known H in F_q^(k×t), and the phase target includes b_x^T H u, then
    c=G_x^T(r+H u)+e,  t0=b_x^T(r+H u)+Delta*K+e0.
For **every** valid z_w with G_x z_w=b_x,
    t0-z_w^T c = Delta*K+e0-z_w^T e.
This is genuine SAME-bit cancellation for distinct valid ORIGINAL representations. But because r was independently uniform, r+H u is also uniform; the exact *entire public source marginal law of (c,t0) conditional on public H and u* equals the original base affine source law. It introduces **no** independently justified security against arbitrary key recovery, and it does not turn structured G_x into uniform-matrix decisional LWE. Publishing u/H and further public data cannot improve that claim. The existence of short representations of G_x z=b_x for false x is likewise unchanged (R156). An exact simulator for related capsules and CK/J/Aux is still missing.

More generally, for simultaneous cancellation the independent columns must annihilate every valid difference d=z_w-z_w'. Enforcing this from the complete solution set without a witness/oracle is itself a real compiler obligation. Choosing an unconstrained uniformly random R gives the failure bound above; choosing R from the readily computable rowspace of G merely folds its secret coefficients into r. This does not rule out nonadditive, computationally hidden nonlinear source encodings or other independently based LWE constructions.

## Assumptions, threat scope and precise handoff

Honest sampling and Open are classical PPT if G is polynomial size and z_w can be computed from w. Adversaries may be arbitrary nonuniform QPT with quantum advice, malicious setup/related capsules and classical selective openings, but **no security reduction is claimed** against them here. The failure is information-theoretic correctness, not a general attack on LWE. The candidate does not even supply fixed-FALSE full-public security, hard-TRUE recovery/native forgery -> ORIGINAL witness, malicious N-of-N abort/erasure, graph/DA/presignatures, SYS/BTC authenticated-source safety, or an actual Bitcoin-native PQ endpoint.

The indispensable next construction must evade this **specific additive independent-column obstruction** rather than paste an ordinary-LWE sample beside an ORIGINAL-dependent phase. Instantiate a *nonlinear, statement-dependent source and every-witness opening jointly with* a straight-line ordinary-QPT-LWE challenge simulator handling all checking/auxiliary/related-capsule correlations, and prove **arbitrary** final-key recovery or native forgery yields an actual ORIGINAL witness or an independent QPT break, without an adversary-provided representation. Per R153, statistical false hiding for all arbitrary NP would imply NP⊆SZK, so computational false security or a different hybrid architecture is essential. No compiler or foundational gap is closed by this run; no efficiency work is justified.

## Exact executed JavaScript checker

~~~javascript
function checkR158(){
  const qs=[5,7,11], T=[1,2,3], rows=[]; let assertions=0;
  const ck=(ok,where)=>{assertions++;if(!ok)throw Error(where)};
  for(const q of qs)for(const t of T){
    let count=0,total=0;
    const power=q**t;
    for(let a=0;a<power;a++){
      let aa=a, ad=Array(t);for(let i=0;i<t;i++){ad[i]=aa%q;aa=Math.floor(aa/q)}
      for(let u=0;u<power;u++){
        let uu=u,phase=0;
        for(let i=0;i<t;i++){phase+=(uu%q)*ad[i];uu=Math.floor(uu/q)}
        if(phase%q===0)count++;total++;
      }
    }
    let expected=power+(power-1)*q**(t-1);
    ck(count===expected,`phase count ${q} ${t}`);
    ck(total===power*power,`total ${q} ${t}`);
    rows.push({q,t,zero_count:count,total,probability:`${count}/${total}`});
  }
  for(const q of qs)for(let r=0;r<q;r++)for(let a=0;a<q;a++)for(let b=0;b<q;b++)for(let u=0;u<q;u++){
    const c0=(r+a*u)%q,c1=(r+b*u)%q;
    ck(((c1-c0-(b-a)*u)%q+q)%q===0,"two witness equality");
    if(a===b)ck(c0===c1,"row span equality");
  }
  for(const q of qs)for(let h=0;h<q;h++)for(let u=0;u<q;u++){
    const got=new Set(Array.from({length:q},(_,r)=>(r+h*u)%q));
    ck(got.size===q,"rowspan uniform shift");
  }
  return {run:"R158",assertions,rows,conclusion:"Independent full-rank LWE pad columns destroy common narrow-phase decryption for two distinct witness representations; witness-annihilator repair makes uniform source rowspan term redundant."};
}
console.log(JSON.stringify(checkR158(),null,2));
~~~

## Captured output from the V8 execution

~~~json
{
  "run": "R158",
  "assertions": 19679,
  "rows": [
    {
      "q": 5,
      "t": 1,
      "zero_count": 9,
      "total": 25,
      "probability": "9/25"
    },
    {
      "q": 5,
      "t": 2,
      "zero_count": 145,
      "total": 625,
      "probability": "145/625"
    },
    {
      "q": 5,
      "t": 3,
      "zero_count": 3225,
      "total": 15625,
      "probability": "3225/15625"
    },
    {
      "q": 7,
      "t": 1,
      "zero_count": 13,
      "total": 49,
      "probability": "13/49"
    },
    {
      "q": 7,
      "t": 2,
      "zero_count": 385,
      "total": 2401,
      "probability": "385/2401"
    },
    {
      "q": 7,
      "t": 3,
      "zero_count": 17101,
      "total": 117649,
      "probability": "17101/117649"
    },
    {
      "q": 11,
      "t": 1,
      "zero_count": 21,
      "total": 121,
      "probability": "21/121"
    },
    {
      "q": 11,
      "t": 2,
      "zero_count": 1441,
      "total": 14641,
      "probability": "1441/14641"
    },
    {
      "q": 11,
      "t": 3,
      "zero_count": 162261,
      "total": 1771561,
      "probability": "162261/1771561"
    }
  ],
  "conclusion": "Independent full-rank LWE pad columns destroy common narrow-phase decryption for two distinct witness representations; witness-annihilator repair makes uniform source rowspan term redundant."
}
~~~

## Independent local Python provenance

An independently written Python 3 stdlib checker in the active container performed the same finite phase-identity and exact counting checks, with **19,679 passing assertions**, reproducing its captured JSON byte-for-byte on a second run. Local-only paths: \`/mnt/data/r158/checker.py\` SHA-256 \`343a75fe6499c7017f07270fa2b725d1f25837c321364215d5631100114ef2a0\`, and \`/mnt/data/r158/captured.json\` SHA-256 \`392063885af9c00b83d78eaee76597a126c5e56f7bebcafb98a2544d5932ecd8\`. Those local artifacts are not represented as published Git blobs; GitHub-only publication here contains the exact executed JS checker and output. No QPT-hardness computation, independent agent, external literature, or web search occurred.
