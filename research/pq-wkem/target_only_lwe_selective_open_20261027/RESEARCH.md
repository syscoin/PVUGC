# Target-only LWE challenge hybrid for adaptively opened SOURCE siblings (restricted)

Date: 2026-10-27. Repository: syscoin/PVUGC PR #1, open/draft/unmerged on research/pq-wkem-validation-20260918. Verified start head: 534500e3870ff94d9c6492cc945eea8bf322123d. Exact predecessor: mixed_capsule_selective_opening_20261027/RESEARCH.md, blob cb08836933823f4511db39bd2f296d0ca3be9b5d. This research is offline and does not claim a generic-NP/BTC WKEM or QPT-certified numerical security.

## New construction/proof: source setup AND the standard-LWE simulator

The earlier restricted mixed-capsule exact row-shift theorem allowed authorized openings of independently keyed true siblings but did not integrate the ordinary QPT-LWE challenge of the surviving random-kernel reference into that adversarial interaction. The repair is a **target-only** hybrid. Do not replace the LWE ciphertexts of an opened sibling by uniform: the opened sibling witness z has Bz=0, so it distinguishes its honest release from uniform with overwhelming advantage. Keep every sibling honest and replace only columns of the eventual unopened target; if that target is adaptive, guess its index before the game and lose at most a factor T over T eligible targets. This yields a genuine straight-line full-joint composition of a restricted source release and an independently assumed ordinary-QPT-LWE challenge, with no SourceOpen oracle or attacker-provided representation.

### Classical release algorithms and the precise restricted SOURCE relation

Let security parameter lambda, modulus q, matrix dimensions d,n, target binary weight h, noise distribution chi, integer g with 1<=g<q and radix m=floor(q/g), and ell=ceil(256/log2(m)). Let e=(1,0,...,0). For every target independently sample **unplanted** B uniformly from F_q^(d x n). Its public restricted source predicate is
R_B(B,z)=[z in {0,1}^n AND sum(z)=h AND z[0]=1 AND Bz=0 mod q].
A public x also carries the declared relation identity, claim/UTXO, branch, anchors/window/context, intended native checking key, and B. Those labels are not proof that a generic ORIGINAL burn/PoW/authorization is actually verified by R_B.

For each capsule i sample independent K_i,U_i,Z_i uniformly from {0,1}^256. Generate the REAL native (sk_i,pk_i)=SeedKeyGen(K_i), publish D_i=U_i XOR Z_i and V_i=K_i XOR U_i, and represent Z_i injectively in ell correlated radix-m digits t_ij. For each j independently sample s_ij uniformly F_q^d and error eps_ij from chi^n, then publish p_ij=B_i^T s_ij+eps_ij+g*t_ij*e mod q. The public data include the true native pk_i=pk(K_i); no independent fake checking key is sampled.

Any valid binary opening z computes z^T p_ij=g*t_ij+z^T eps_ij mod q, decodes the digits, reconstructs Z_i and recovers the SAME precommitted K_i=V_i XOR D_i XOR Z_i. Distinct valid z may have distinct intermediate vectors. For independent ternary eps in {-1,0,1} and Delta=min(g,q-(m-1)g), the deterministic condition 2h<Delta gives simultaneous correctness for ALL valid z, without sampling a chosen witness. For subgaussian error sigma the explicit (possibly vacuous) all-witness failure union bound is 2 ell binom(n-1,h-1) exp(-Delta^2/(8h sigma^2)). No claim of QPT security for the finite toy choices below.

Only the TARGET B_i must be uniform and the SOURCE predicate must be precisely R_B. Other related capsules may use independently samplable structured matrices, including honestly opened true-source siblings, with independently sampled native K, U, Z and source coins. Their complete public view, known witnesses and permitted native signatures remain real. They can depend on the target's public pk/context if their generator remains classical PPT without the target seed. They must not expose target secret pads/seed or a target valid opening through special auxiliary leakage, and cannot reuse the target's source kernel unless cross-claim witness transfer is intended and authorized.

### QPT security game and full-public hybrid

An arbitrary QPT attacker receives all target/sibling public matrices, x, capsule columns, actual native checking keys, contexts and reproducible auxiliary data. Its interaction uses CLASSICAL opening/signature queries; it can coherently process all classical transcripts and maintain arbitrary polynomial quantum state, including efficiently generated quantum advice. It can adaptively disclose independently keyed sibling K/U/Z and accepted witness and obtain their valid signatures. This models off-chain local releases, NOT an online committee. Target disclosure is excluded from an unauthorized win; the target challenge message must not have been signed previously. All target-key-dependent auxiliary data must be generated from its public pk and allowed signing oracle, not unknown seed-dependent side information. The native EUF-CMA assumption is required for precisely this classical-query QPT signing interface.

For an unopened target i, a QPT decisional-LWE challenger supplies B_i uniform and either y=B_i^T s+eps or y uniform in F_q^n. In a column-by-column hybrid the reduction (which knows K_i,U_i,Z_i at this stage) embeds p_ij=y+g*t_ij e, draws all other target columns honestly from that SAME B_i, and generates every other sibling and authorized opening/signature honestly. It needs neither a target witness nor a false-source row-shift certificate. Moving target column j from LWE to uniform costs at most Adv_QPT-DecLWE(d,n,q,chi). Each target column uses an independent s_j, so sum over ell columns gives ell*Adv. Crucially, a sibling with revealed witness is NEVER switched to uniform; its opened public ciphertext and checking-key correlations are unchanged in every hybrid. The adversary may adaptively select the siblings to open in response to the target transcript, and the reduction remains straight-line with no rewinding, random oracle extraction or quantum lifting claim.

After all target p_j become uniform they are independent of all t_j(Z_i). For each fixed native K_i (and thus fixed genuine native pk_i) the map (U_i,Z_i)->(D_i=U_i XOR Z_i,V_i=K_i XOR U_i) is a bijection. Therefore (D_i,V_i) is a pair of independent uniform strings even conditional on K_i, its pk_i, target B_i, and honestly generated independent sibling disclosures/signing transcripts. This is a joint conditional equality, NOT a marginal pad-hiding assertion. Now a simulator given a REAL native EUF-CMA challenge pk_i, with no K_i, publishes uniform target p_j,D_i,V_i, generates all siblings honestly, and forwards the allowed target native signing queries. An accepted fresh target native signature is its EUF-CMA forgery. If the attacker instead outputs a usable native seed K' whose deterministic SeedKeyGen produces pk_i, the simulator runs SeedKeyGen(K') and signs an unqueried target message, also forging.

For a fixed unopened target:
Pr[seed recovery or fresh intended-path native forgery] <= ell*Adv_QPT-DecLWE(d,n,q,chi)+Adv_QPT-EUF-CMA(native).
For an adaptively chosen winning target among at most T eligible capsules, sum these bounds across targets (or guess the target index with a T loss). Advantages allow the described classical adaptive interfaces and efficient QPT processing; advice depending on undisclosed target coins is outside the stated game. The statement is **average-case over UNCONDITIONED uniform target B**, not a theorem for attacker-selected fixed false x, a planted B, or a distribution conditioned on source truth. Ordinary-QPT-LWE hardness and QPT-native EUF-CMA are independently required; no concrete 128-bit estimate or deployed native BTC verifier is asserted.

### Why target-only switching is necessary

For an honestly opened sibling with known weight-h witness w and ternary errors, the revealed digit t obeys |w^T p_s-g*t|_q<=h in EVERY real draw. If a proof instead replaced that sibling p_s by uniform then w^T p_s is uniform F_q and satisfies this inequality with probability exactly (2h+1)/q for q>2h. An adversary can distinguish. This is not a failure of ordinary LWE: its auxiliary data now contain a short kernel witness for the very matrix being challenged. The correct target-only reduction retains the sibling's honest p_s and gives its witness and key to the adversary without ever trying to hide that sibling.

A second explicit boundary is that publicly reusing B across independently challengeable scopes lets a known sibling witness decrypt the target, even when native keys differ. With truly independent uniform target B and a fixed nonzero sibling witness w, B_target*w is uniform in F_q^d; conditional on nonzero, w^T B_target^T s is exactly uniform in F_q for fresh uniform s. This is only a single-projection identity, not a proof of the full joint game. The target's joint computational security comes from the independent QPT decisional-LWE hybrid above.

### Exact finite executable checks and provenance

The self-contained JS checker below was ACTUALLY executed in V8 twice with byte-identical JSON output before publication. Toy q=257,d=2,n=5,g=16,radix16,ell64,h=2, bounded ternary errors. It checks two distinct valid sibling witnesses opening the SAME 256-bit seed, 16 full checking-key-conditioned (U,Z)->(D,V) bijections, native seed leak under an invalid reused matrix, exact 5/257 opened-sibling distinguisher, and a 257-residue target scalar projection with independent B. Its toy PK function is a deterministic placeholder, NOT an SLH signer. Independent local standard-library Python ran twice with identical stdout (4,926 assertions/run), using q=65537,d=3,n=6,g=512,radix128,ell37, 2 distinct valid sibling openings and the same mathematical boundaries. Source SHA-256: 38cb39cb0bdd79f77aff615ed911dd942ddcee1d6985624dac691305a354ac6a. Output SHA-256: d010abf813307a186b4fa59638769b97da95367e83416fca0391bee978005cf6. Full local provenance/derivation/checker/output archive SHA-256: 5b37b38736fa66a6cfc2265389d4f2a2341621f2246f7b79d4d076c68b9cb545. No external research or agents.

### Exact missing ORIGINAL equation

Need one classical-PPT compiler for arbitrary ORIGINAL (x,R_ORIGINAL) satisfying B_x f_x(W)=0 for **every** valid ORIGINAL W with a SAME precommitted K, while an ordinary-QPT-LWE reduction can jointly generate the complete source-dependent B_x/statement/capsule/native pk/context/auxiliary/related-capsule distribution without a source-opening oracle, hidden common-preimage assumption, or attacker's volunteered representation. Must establish full-public security for every false x and arbitrary hard-true key recovery/native forgery -> ORIGINAL W or independent QPT break. The random-B relation here does not supply that compiler. Malicious N-of-N preauthorization, bypass exclusions, erasure/abort/data availability, PoW fork/ChainLock validation, P2MR-like/native SLH-like endpoint, and transaction graph remain separate and unproved. This is a restricted composition result, NOT completed witness encryption.

## Exact executable checker (executed before publication)

```javascript
const verifyTargetOnly = function verifyTargetOnly(){
  const q=257,g=16,m=16,ell=64,n=5,d=2,h=2;
  let assertions=0, state=0x51a74eed;
  const check=(v)=>{if(!v)throw Error("offline JS assertion "+assertions); assertions++;};
  const rand=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;};
  const mod=(x)=>((x%q)+q)%q;
  const dot=(a,b)=>a.reduce((s,v,i)=>s+v*b[i],0);
  const Bw=(B,w)=>B.map(row=>mod(dot(row,w)));
  const bytes=()=>Array.from({length:32},()=>rand()&255);
  const X=(a,b)=>a.map((v,i)=>v^b[i]);
  const eq=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
  const padDigits=(z)=>z.flatMap(x=>[x>>4,x&15]);
  const fromDigits=(t)=>t.filter((_,i)=>i%2===0).map((hi,j)=>(hi<<4)|t[j*2+1]);
  const w0=[1,1,0,0,0],w1=[1,0,1,0,0];
  const Bs=Array.from({length:d},()=>{const a=rand()%q;return[a,mod(-a),mod(-a),rand()%q,rand()%q]});
  const Bt=Array.from({length:d},()=>Array.from({length:n},()=>rand()%q));
  [w0,w1].forEach(w=>{check(Bw(Bs,w).every(x=>x===0));check(w[0]===1&&w.reduce((a,b)=>a+b,0)===h);check(Bw(Bt,w).some(x=>x!==0));});
  const Ks=bytes(),Kt=bytes(),Us=bytes(),Ut=bytes(),Zs=bytes(),Zt=bytes();
  const Ds=X(Us,Zs),Vs=X(Ks,Us),Dt=X(Ut,Zt),Vt=X(Kt,Ut);
  check(eq(X(Vs,X(Ds,Zs)),Ks));check(eq(X(Vt,X(Dt,Zt)),Kt));
  function encrypt(B,z){
    return padDigits(z).map(t=>{
      const s=[rand()%q,rand()%q],e=Array.from({length:n},()=>rand()%3-1);
      const p=Array.from({length:n},(_,i)=>mod(B[0][i]*s[0]+B[1][i]*s[1]+e[i]+(i===0?g*t:0)));
      return {p,e,t};
    });
  }
  function recover(B,w,cols){
    check(Bw(B,w).every(v=>v===0));
    const ts=cols.map(({p,e,t})=>{
      const v=mod(dot(w,p));
      let nearest=-1, distance=q;
      for(let j=0;j<m;j++){const z=mod(v-g*j),dist=Math.min(z,q-z);if(dist<distance){distance=dist;nearest=j;}}
      check(distance<=h);check(nearest===t);check(mod(dot(w,e))===mod(v-g*t));
      return nearest;
    });
    return fromDigits(ts);
  }
  const cs=encrypt(Bs,Zs),ct=encrypt(Bt,Zt);
  [w0,w1].forEach(w=>{check(eq(recover(Bs,w,cs),Zs));check(eq(X(Vs,X(Ds,recover(Bs,w,cs))),Ks));});
  const cbad=encrypt(Bs,Zt);
  [w0,w1].forEach(w=>{const z=recover(Bs,w,cbad);check(eq(z,Zt));check(eq(X(Vt,X(Dt,z)),Kt));});
  const delta=v=>Math.min(mod(v),q-mod(v));
  check(Array.from({length:q},(_,a)=>delta(a)<=h).filter(Boolean).length===2*h+1);
  cs.forEach(({p,t})=>[w0,w1].forEach(w=>check(delta(dot(w,p)-g*t)<=h)));
  [w0,w1].forEach(w=>{const c=Bw(Bt,w).find(v=>v!==0);check(new Set(Array.from({length:q},(_,s)=>mod(c*s))).size===q);});
  for(let k=0;k<16;k++){
    const seen=new Set();
    for(let u=0;u<16;u++)for(let z=0;z<16;z++)seen.add(((u^z)<<4)|(k^u));
    check(seen.size===256);
  }
  const pkToy=k=>k.reduce((a,b)=>(a*131+b)>>>0,0);
  check(pkToy(Ks)!==pkToy(Kt));
  check(g*(m-1)<q && 2*h<Math.min(g,q-(m-1)*g));
  check(m**ell >= 2**256);
  return {status:"PASS",assertions,q,g,m,columns:ell,n,d,opened_sibling_witnesses:2,
    naive_uniform_sibling_acceptance:`${2*h+1}/${q}`,target_scalar_projection_uniform_residues:q,
    checking_key_conditioned_pad_bijections:16,unsafe_shared_matrix_recovers_full_target_seed:true,
    note:"Toy exact algebra only. No LWE or native QPT hardness test."};
};
console.log(JSON.stringify(verifyTargetOnly()));
```

## Captured checker JSON, two identical executions

```json
{"status":"PASS","assertions":1324,"q":257,"g":16,"m":16,"columns":64,"n":5,"d":2,"opened_sibling_witnesses":2,"naive_uniform_sibling_acceptance":"5/257","target_scalar_projection_uniform_residues":257,"checking_key_conditioned_pad_bijections":16,"unsafe_shared_matrix_recovers_full_target_seed":true,"note":"Toy exact algebra only. No LWE or native QPT hardness test."}
{"status":"PASS","assertions":1324,"q":257,"g":16,"m":16,"columns":64,"n":5,"d":2,"opened_sibling_witnesses":2,"naive_uniform_sibling_acceptance":"5/257","target_scalar_projection_uniform_residues":257,"checking_key_conditioned_pad_bijections":16,"unsafe_shared_matrix_recovers_full_target_seed":true,"note":"Toy exact algebra only. No LWE or native QPT hardness test."}
```
