# R121 — Global noisy-projective ORIGINAL 3-CNF source (REJECTED)

**Conclusion:** NO positive secure generic witness-KEM advance. One explicitly instantiated classical-PPT ORIGINAL-dependent release and complete fixed-FALSE counterexample. This investigates a global projective-hash alternative to R120's unique-proof proposal; it is **not** an optimization and is **not** a secure successor to the broken R111/R112 source.

**Provenance:** Offline, 2026-11-06; continuity syscoin/PVUGC#1 branch research/pq-wkem-validation-20260918; starting head af633f7122b3347a32d152d032e1c2ae547ed6c7; read actual PR metadata, latest ordinary comment 6695356444 and exact-version R119 note (blob 9b7bbea54db0e87678fec511f2b585178421e87c). Read R120 local-only RESEARCH.md for its precise unfinished step. No external research. The independent local Python checker ran twice with byte-identical captured JSON and 35,585 assertions; the executable V8 checker below was actually run and its exact returned JSON is recorded below. Neither is a QPT-hardness test.

## Explicit global ORIGINAL compiler and release

Take arbitrary 3-CNF R_x(w) with n Boolean variables and m clauses. Create 2 integer coordinates (z_i,0,z_i,1) for each variable and 3 (c_j,0,c_j,1,c_j,2) for each clause. Let A_x be the (n+2m) × (2n+3m) integer matrix consisting of variable group sums z_i,0+z_i,1=1, clause group sums c_j,0+c_j,1+c_j,2=1, and for each clause j the equation

    sum_{literal occurrence (i,b) satisfied by bit b} z_i,b + c_j,1+2*c_j,2 = 3.

Let b_x be the vector of group ones and clause threes, so A_x z=b_x. For each ORIGINAL satisfying w create its one-hot z_w and, for clause j with s_j true occurrences (1≤s_j≤3), set c_j,3-s_j=1. This yields A_x z_w=b_x and ||z_w||_1=||z_w||_2²=n+m, regardless of WHICH valid witness was supplied. No canonical witness, common preimage or SOURCE opening oracle is used.

**Supplied-short-vector semantic lemma:** If an integral z obeys the group sums and ||z||_2²≤n+m, each group must attain its integer minimum squared norm 1 and hence is one-hot. Clause equations then enforce the ORIGINAL CNF. For modular q, choose q larger than all row magnitudes possible at that norm, preventing wrap. This only establishes supplied-short-representation → ORIGINAL witness, NOT recovery → representation.

**Public release:** For each pad bit B_t of a frozen native signature sigma bound to actual relation identity, claim/UTXO, branch, anchors/window, context, intended native VK/message and graph, choose prime q and two far-separated public residues h_0,h_1. Classical PPT setup samples alpha_t uniformly over the affine hyperplane alpha_t·b_x=h_{B_t} mod q (sample all but a coefficient of a group-sum 1 and solve the last) and e_t uniform in [-E,E]^(2n+3m). Publish p_t=A_x^T alpha_t+e_t mod q, D=sigma XOR B, A_x,b_x, public CK/J/Aux/context and related capsules. An off-chain opener with actual ORIGINAL w computes z_w and rounds p_t·z_w to the nearer center, obtaining B_t and the SAME frozen sigma. Provided the decoding threshold exceeds E(n+m), correctness holds for every permitted noise tape and every valid witness, even when witnesses' one-hot states differ. Native verification occurs solely on the resulting conventional signature at the conditional endpoint; no Bitcoin NP verification is assumed.

**Attempted full-public security game:** x, A_x,b_x, all p_t, D, VK/M, CK,J,Aux, context, graph, all related capsules, permitted classical openings and arbitrary QPT quantum advice are visible. Honest setup is classical PPT and independent pad/key instances are jointly generated; malicious setup, selective openings and QPT simulation would require their own proof. In fact the fixed-FALSE case below breaks source hiding before any such proof opportunity arises.

## Complete deterministic fixed-FALSE counterexample

Set x=(X∨X∨X)∧(¬X∨¬X∨¬X), with variable group (z0,z1) and 3-coordinate slack group for each clause. This ORIGINAL relation has NO witness. Nevertheless the public integer vector

    z_bad = (0,1 ; 1,0,0 ; 0,-1,2)

obeys A_x z_bad=b_x exactly, with ||z_bad||²=7>n+m=3 and ||z_bad||_1=5. It fails the **cooperative off-chain** norm check but the attacker never calls that verifier. From public p_t it calculates

    <p_t,z_bad> = <alpha_t,b_x> + <e_t,z_bad> (mod q).

With q=1009, h_0=252, h_1=756 and E=1, the error's absolute value is at most 5 while centers have cyclic distance 504. Thus the attacker identifies B_t by nearest-center rounding on EVERY allowed setup/error tape, without an ORIGINAL witness. Repeating per pad bit recovers the entire precommitted native signature, and directly violates FALSE-instance full-public-output security. Public CK/J/Aux or related capsules cannot erase the already-public linear projection. There is no ordinary LWE break; this design specially conditions alpha on the hidden bit and leaks its target functional by the longer public integer representation.

For TRUE instance (X∨X∨X) with independent free variable Y, the distinct ORIGINAL satisfying witnesses (X,Y)=(1,0) and (1,1) generate different one-hot vectors with norm²=3 and decode the same bit. Same-capability correctness therefore does NOT imply false-instance security.

**Repair check:** Adding a public norm-verification flag does not prevent the projection. Raising q only widens the key-center gap relative to the bad projection's bounded error. Lowering q/increasing E enough to disrupt the bad projection also introduces noisy decoding for valid ones, and the attacker has multiple correlated near representations; no independently established nonlinear global gating/simulation was found. Thus this source is rejected, not an unproven secure candidate. The exact remaining obligation is a polynomial-size ORIGINAL-dependent source with SAME capability for all w and a genuine full-public QPT simulator and reduction from arbitrary recovery/native forgery to ORIGINAL witness or independent PQ break, with no adversary-volunteered intermediate representation. N-of-N setup/abort, data availability, numerical PQ calibration and native Bitcoin endpoint remain separate outstanding obligations.

## Exact independently executed V8 checker

~~~javascript
function checkR121() {
  const q=1009, cs=[252,756], A=[
    [1,1,0,0,0,0,0,0],
    [0,0,1,1,1,0,0,0],
    [0,0,0,0,0,1,1,1],
    [0,3,0,1,2,0,0,0],
    [3,0,0,0,0,0,1,2]
  ], b=[1,1,1,3,3], bad=[0,1,1,0,0,0,-1,2];
  const T=[
    [1,1,0,0,0,0,0],
    [0,0,1,1,0,0,0],
    [0,0,0,0,1,1,1],
    [0,3,0,0,0,1,2]
  ], bt=[1,1,1,3],
  good0=[0,1,1,0,1,0,0], good1=[0,1,0,1,1,0,0];
  let assertions=0, fs=0, ts=0, cnt=0;
  function ok(x) {assertions++; if(!x) throw Error("R121 assertion "+assertions);}
  const dot=(u,v)=>u.reduce((s,x,i)=>s+x*v[i],0);
  const mv=(M,v)=>M.map(r=>dot(r,v));
  const mod=a=>(a%q+q)%q;
  function sampleAlpha(target, bit) {
    const a=target.map((_,i)=>i===0?0:mod(7+37*i+101*bit));
    a[0]=mod(cs[bit]-dot(a,target)); ok(mod(dot(a,target))===cs[bit]); return a;
  }
  function pub(M,a,e) {
    return e.map((x,i)=>mod(x+M.reduce((s,row,j)=>s+row[i]*a[j],0)));
  }
  function guess(p,z) {
    const h=mod(dot(p,z));
    const dist=c=>Math.min(mod(h-c),mod(c-h));
    return dist(cs[1])<dist(cs[0])?1:0;
  }
  function noise(t,d) {
    const e=[];for(let i=0;i<d;i++){e.push((t%3)-1);t=Math.floor(t/3);}return e;
  }
  ok(JSON.stringify(mv(A,bad))===JSON.stringify(b));
  ok(dot(bad,bad)===7);
  ok(bad.reduce((s,x)=>s+Math.abs(x),0)===5);
  ok(JSON.stringify(mv(T,good0))===JSON.stringify(bt));
  ok(JSON.stringify(mv(T,good1))===JSON.stringify(bt));
  ok(dot(good0,good0)===3 && dot(good1,good1)===3);
  for(let t=0;t<3**8;t++){
    const z=noise(t,8);
    if(dot(z,z)<=3){cnt++;ok(JSON.stringify(mv(A,z))!==JSON.stringify(b));}
  }
  ok(cnt===577);
  for(let bit=0;bit<2;bit++){
    const a=sampleAlpha(b,bit);
    for(let t=0;t<3**8;t++){
      const e=noise(t,8),p=pub(A,a,e);
      ok(guess(p,bad)===bit);
      const delta=mod(dot(p,bad)-cs[bit]);
      ok(delta===mod(dot(e,bad)));fs++;
    }
    const at=sampleAlpha(bt,bit);
    for(let t=0;t<3**7;t++){
      const p=pub(T,at,noise(t,7));
      ok(guess(p,good0)===bit && guess(p,good1)===bit);ts++;
    }
  }
  ok(fs===13122 && ts===4374);
  return {run:"R121-GLOBAL-NOISY-PROJECTIVE-SOURCE-20261106",assertions,short_candidates:cnt,false_noise_bit_cases:fs,true_noise_bit_cases:ts,outcome:"FALSE-instance pad recovered for every enumerated permitted noise vector; rejected"};
}
const result=checkR121();
console.log(JSON.stringify(result));
~~~

## Captured V8 output

~~~json
{
  "run": "R121-GLOBAL-NOISY-PROJECTIVE-SOURCE-20261106",
  "assertions": 31207,
  "short_candidates": 577,
  "false_noise_bit_cases": 13122,
  "true_noise_bit_cases": 4374,
  "outcome": "FALSE-instance pad recovered for every enumerated permitted noise vector; rejected"
}
~~~

**Local independent expanded checker:** /mnt/data/R121_global_projective_source_20261106/checker.py (local only; SHA-256 c0188826a0df4291fe4d827198291a06246c4f74a07d70c7d0e7f04f84d76ea2); local notes/captured hashes and duplicate execution are preserved in an archive separately, not claimed as GitHub published. Research result is negative; optimization gate remains closed.