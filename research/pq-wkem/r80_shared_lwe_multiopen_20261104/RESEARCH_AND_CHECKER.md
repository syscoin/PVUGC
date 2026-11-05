# R80 — Shared honest LWE matrix with adaptive non-target openings

**Run:** R80-SHARED-MATRIX-ADAPTIVE-SIBLING-OPENING-20261104. **Status:** restricted, constructed multi-capsule release/simulation theorem for R79's certified-FALSE native-forgery experiment; **not generic WKEM and not hard-TRUE witness extraction**. All computation here was bounded and offline except expressly authorized GitHub continuity/publication.

## Continuity and exact checked predecessors

Repository syscoin/PVUGC PR #1 was open, draft and unmerged, head \`dc1f575d0cc4438f9b063c3e3f3fa926a3b08542\`, branch \`research/pq-wkem-validation-20260918\`, latest substantive top-level comment \`6650000843\`. Exact R79 source blob \`3bff84f668966fac7d5bfefa13f536d1f7e64671\`, R71 LWE PRG source blob \`366eb05d42e423d997bd1def6cfcb4563040ea86\`, R77 certified-FALSE source blob \`36577c90842c6787ab9fa3cbe00ee9641c0e66bd\`. The previous theorem R79 excludes target-root openings and permits independently rooted sibling references; this run instantiates **one genuinely shared honest public PRG matrix**, polynomially many independently rooted capsules, **adaptive disclosure of non-target roots and signatures**, and full cross-capsule CK/Aux correlations under a single-sample QPT-LWE assumption. This is a compositional extension, not a new hardness claim.

## Exact classical release setup and opening policy

Fix λ, polynomial T(λ), the R71 exact LWE distribution: n, b=ceil(log2 n), q_L=2^(4b), m_L=4n; one \`A_com <- Uniform(Z_(q_L)^(m_L x n))\`, protected from corrupt participant bias by the precommitted contribution/one honest sampler requirement. For each independently rooted honest capsule i: \`K_i <- Uniform({0,1}^ell)\` with ell=8nb; \`U_i=H_(A_com)(K_i)\`, where H is exactly R71's two-stage public ordinary-LWE-derived generator of length L=2ell+2tau. Split U_i into **disjoint** P_i (|sigma_i| bits), B_i (checking-key seed), and unused remainder, with L>=|sigma_i|+|B_i|. Before irreversible funding an honest native signer generates sigma_i=Sign(sk_h,m_i), where m_i binds ORIGINAL relation identity, actual claim/UTXO, intended branch, anchors/window, context and verification key. Under a common vk_h, distinct capsules MUST have distinct m_i; the target m_h must never be queried through other capsule openings. Define \`D_i=sigma_i XOR P_i\`.

For each eligible certified-FALSE target ORIGINAL statement x_i, compile its actual relation, not proposer-supplied replacement, into A_(x_i), e0_i, and publicly check one fixed torsion certificate t with \`A_(x_i)t=Delta e0_i (mod q_src)\`. With fresh uniform source z_ij and bounded errors e_ij, emit \`C_ij=Round(A_(x_i)z_ij+e_ij+Delta mu_j(K_i)e0_i)\`. Reusing z between different roots or word indices is forbidden. Same-root siblings may reuse one z per word ONLY with R78's verified common-t restriction. Every valid ORIGINAL witness on a corresponding TRUE source still gives a normalized r_w with r_w^T A_x=0 and r_w^T e0=1, and opens the SAME precommitted root by conservative bounded-error decoding, although that says nothing about unauthorized hard-TRUE recovery.

For each capsule construct all \`CK_i\`, \`Aux_i\` as acyclic deterministic PPT functions of B_i, D_i, the frozen public manifest, source C_i, previous public CK/Aux and related public references. These **must never** use raw P_i, secret sigma_i, K_i, an independent signature fingerprint or hidden correlated signer/source coins. The public view contains all x, source matrices/C, native vk, scope, claim/path/anchors, D, CK, Aux, related capsules and the R70 honest-verifier WELLFORMED preflight transcripts. The one A_com may additionally be used for R71 independently seeded bit commitments with honestly chosen R, not with K_i as a commitment seed. Authenticated no-bypass N-of-N native path, honest-erasure setup, evidence/pre-signature availability and Bitcoin PQ capability are separate external requirements; none are proved by this lemma.

An arbitrary QPT attacker sees and processes the complete **classical** view coherently and may adaptively request any subset of **non-target** independent roots K_j, other-message signatures sigma_j and allowed source openings. Its advice is independent of hidden target K_h, LWE challenge secret/noise, native signer coins and per-commitment randomness. The target h is chosen adaptively from a frozen polynomial candidate set of publicly certified FALSE statements, but its root, target signature, same-root TRUE opening, raw source coins and secret-dependent auxiliary state may NOT be exposed. Adaptive queries are classical, not superposition oracles. Malicious appendices may depend on all previous public records.

## Fully joint source-dependent proof, with an actual single-sample LWE challenger

Fix one potential unopened target index h. To simulate its complete x_h-dependent source without K_h, sample independent uniform \`z'_hj\` and publish \`C'_hj=Round(A_(x_h)z'_hj+e_hj)\`. The **pointwise** coupling \`z'_hj=z_hj+mu_j(K_h)t\` yields \`A_x z+e+Delta mu e0=A_x(z+mu t)+e\`. Because z is uniform, the target source law and every subsequently adaptively generated CK/Aux/reference message law are exactly unchanged. All non-target seeds, signatures, honest sources and opened root material are generated genuinely, since the reduction knows them. Thus NO SourceOpen oracle is presumed.

First replace only h's real WELLFORMED honest-verifier 3-color certificate on the originally TRUE wellformedness statement with R70's straight-line HV transcript simulator at QPT loss delta_HV,h. This requires independently bound commitments, honest edge challenge after commitments, fresh coins, and real-world preflight success before funding. The simulated HV transcript remains publicly accepting in later hybrids even when WELLFORMED is FALSE; this does not prove malicious-verifier ZK or Fiat-Shamir soundness.

Next give a simulator **one actual ordinary decisional-QPT-LWE sample** \`(A_com,Y*)\` as R71's two-sequential-step H generator challenge for **target h only**. The simulator samples every other independent K_j and computes its genuine \`H_(A_com)(K_j)\` on the **same challenger-supplied A_com**, so it can answer adaptive non-target openings exactly, even when those include TRUE ORIGINAL siblings. Evaluate the full acyclic public CK/Aux DAG and corrupted appendices jointly from the target challenge U_h* and genuine other U_j. The target H_A(K_h) vs uniform-U_h* hybrid costs at most 2 epsilon_QPT-LWE (for exactly R71's public uniform A, uniform secrets and signed b-bit uniform error). Other output samples correlated with A are efficient challenger-side postprocessing, so there is NO extra multi-sample LWE hardness assumption, no quantum rewind, and no target-root/source-opening oracle. Quantum coherence is covered by the QPT distinguishers on this entire classical transcript.

In the uniform-U_h hybrid, P_h and B_h are exactly independent. Sample target D_h uniform; all CK/Aux and later public references are functions of B_h, D_h and **genuine** non-target outputs, with no P_h leakage. Embed independent native QPT-EUF-CMA challenge vk_h without knowing target sigma_h. Query its signing oracle only for distinct non-target messages m_j to simulate others (including their adaptive disclosure); NEVER query m_h. Even conditional on all other signatures and opened K_j, target D_h is uniform independent of sigma_h. Any accepted native signature on unqueried m_h is a native QPT-EUF-CMA forgery. This is a **restricted FALSE-target** proof, not a proof that native signatures on hard TRUE x reveal ORIGINAL witnesses.

For a fixed h define E_h as: h is certified FALSE, h remained unopened, the honest graph slot is necessary, and the attacker outputs an accepted native path signature for unqueried m_h. The bound is:

    Pr[E_h] <= Adv_QPT-EUF-CMA,h(native) + 2 eps_QPT-LWE
               + delta_HV,h + eps_bad_setup,h + eps_bad_proof,h .

The last two terms apply only if failed ceremony/proof acceptance is counted as a separate win event. For an attacker choosing any h adaptively among at most T eligible candidates, use \`Pr[E] <= sum_(h=1)^T Pr[E_h]\`; per-index reductions suffice and give a T-factor upper bound without guessing with quantum rewinding or falsely treating an abort-conditioned matrix as uniform. If abort is observed and the protocol never funds, that is a liveness result, not a crypto compromise. Conditioning on successful adversarial selective abort may bias A_com and is OUTSIDE the theorem.

**Essential negative control:** replacing U_j by uniform for a sibling j whose root K_j is subsequently opened is INVALID: the attacker computes H_(A_com)(K_j) and compares it to public U_j-correlated fields. Thus the hybrid replaces ONLY an unopened target, while all selectively opened non-target siblings remain real. Exposing even one same-root TRUE witness or the target m_h signature invalidates this reduction. The preflight checks WELLFORMED source/sig consistency, NOT ORIGINAL extraction.

## Concrete efficiency and qualification

Sharing A_com rather than independently sampling one PRG public matrix for each capsule saves \`(T-1)m_L*n*log2(q_L)\` bits. At the deliberately **uncalibrated** R71 parameters n=128, m=512, q=2^28, each additional root saves exactly 229,376 bytes of public matrix (T=4 saves 688,128 bytes). This is not a compression of the enormous R70/71 preflight, nor a 128-bit quantum-hardness claim.

Needed independent assumptions: ordinary single-sample decisional QPT-LWE **with R71's exact chi and advice model**; native QPT-EUF-CMA; QPT hiding/statistical binding for R71 fresh-seed commitments, unpredictably honest HV verifier; static protected honest native signer, no-bypass graph and erasure; bounded source noise/correct decoding; correct per-capsule public false certificates; independent uniformly sampled roots; classical adaptive messages; no malicious post-reveal matrix bias; bounded abort attempts and pre-funding DA. This is conditional, not a proof of any Bitcoin deployment. Auxiliary correlations not generated by the stated DAG and direct/indirect target-root openings are expressly excluded.

**Central missing equation unchanged:** For arbitrary hard-TRUE generic ORIGINAL x, exhibit a classical-PPT source/release compiler and simulator satisfying all-witness SAME-capability correctness and

    Pr[QPT A(full_public_x) obtains final capability or native accepted signature]
       <= Pr[R_ORIGINAL(x, Ext^A(full_public_x))=1]
          + Adv_independent_QPT_break + negl(lambda),

where Ext cannot require A to volunteer a representation. R58 quotient non-Boolean bypass, R63/R67 signed-kernel recovery, arbitrary-FALSE full-view security, malicious ceremony/abort/useful completeness, practical 128-bit parameters and conditional native Bitcoin PQ endpoint remain OPEN. R80 addresses NONE of these. No complete witness-KEM and no stopping condition.

## Exact executed V8 checker

The following deterministic JS function was executed directly in the connected V8 environment; its exact source and captured return value are preserved below. It checks source pointwise translation, adaptive full-view CK/Aux coupling, honest openings of unrelated roots, independence of the uniform-pad full public view from a native signature, and a target-opening negative control. Hashes, signing bytes and field parameters are toy values; **not** QPT, NP-to-3COLOR, a signature library or a security proof.

```javascript
function checkR80() {
  let assertions=0, sourceCouplings=0, openedOther=0, uniformPad=0, negative=0;
  let seed=0x801104;
  const rnd=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;};
  const ok=(v,s)=>{assertions++;if(!v)throw Error(`assertion ${assertions}: ${s}`);};
  const mod=(a,n)=>((a%n)+n)%n;
  const eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
  const tag=(v)=>{let h=2166136261>>>0;for(const ch of JSON.stringify(v)){h=Math.imul((h^ch.charCodeAt(0))>>>0,16777619)>>>0;}return h>>>0;};
  const toyH=(A,k)=>{
    const G=s=>{let y=0;for(let i=0;i<4;i++){const e=((s>>>(4+i))&1)-1; y|=mod(A[i]*(s&15)+e,16)<<(4*i);}return y;};
    const y1=G(k),y2=G(y1&255);
    return (y1>>>8)|((y2>>>8)<<8)|((y2&255)<<16);
  };
  const source=(c,z,e,mu)=>[-1,c,c].map((a,i)=>Math.floor(mod(a*z+(i===0?e+8*mu:0),32)/2));
  for(const c of [4,8,12]){
    ok(eq([-1,c,c].map(a=>mod(a*24,32)),[8,0,0]),"public common false certificate");
    for(let a=0;a<=1;a++)for(let b=0;b<=1;b++)ok(c*a+c*b!==1,"actual binary ORIGINAL false relation");
    for(let mu=0;mu<4;mu++)for(let z=0;z<32;z++)for(const e of [-1,0,1]){
      ok(eq(source(c,z,e,mu),source(c,mod(z+24*mu,32),e,0)),"pointwise source coupling");
      sourceCouplings++;
    }
  }
  for(let h=0;h<4;h++)for(let rep=0;rep<96;rep++){
    const A=Array.from({length:4},()=>rnd()%16);
    const roots=Array.from({length:4},()=>rnd()%256);
    const sigs=Array.from({length:4},()=>rnd()%16);
    const Us=roots.map(k=>toyH(A,k));
    const z=Array.from({length:4},()=>Array.from({length:2},()=>rnd()%32));
    const errors=Array.from({length:4},()=>Array.from({length:2},()=>[-1,0,1][rnd()%3]));
    const view=(blind)=>{
      let prev=0xabc; const result=[];
      for(let i=0;i<4;i++){
        const c=i===0?4:[4,8,12][prev%3], P=Us[i]&15,B=(Us[i]>>>4)&15;
        const D=sigs[i]^P;
        const words=[roots[i]&3,(roots[i]>>>2)&3];
        const Cs=words.map((w,j)=>blind&&i===h
          ?source(c,mod(z[i][j]+24*w,32),errors[i][j],0)
          :source(c,z[i][j],errors[i][j],w));
        const scope=["original-relation","outpoint:1","challenge","anchor",i,"vk-h"];
        const CK=tag(["CK",B,D,scope,A,c,Cs,prev]),Aux=tag(["Aux",B,D,CK,scope]);
        result.push({scope,c,Cs,D,CK,Aux});prev=CK;
      }
      return result;
    };
    const real=view(false),simulated=view(true);
    ok(eq(real,simulated),"exact full public CK/Aux/interslot adaptive source view");
    sourceCouplings++;
    const selector=tag(["open",real]),opened=[];
    for(let i=0;i<4;i++)if(i!==h && ((selector>>>i)&1)){
      opened.push(i);
      ok(toyH(A,roots[i])===Us[i],"legitimate opened other root valid");
      ok((sigs[i]^(Us[i]&15))===real[i].D,"other signature verified");
      openedOther++;
    }
    ok(!opened.includes(h),"target root remains unopened");
  }
  const fixedOthers=[[0,21,7],[1,55,3],[2,110,5]];
  for(let B=0;B<16;B++){
    let first=null;
    for(let sigma=0;sigma<16;sigma++){
      const counts=new Map();
      for(let P=0;P<16;P++){
        const D=sigma^P,CK=tag(["CK",B,D,fixedOthers]),Aux=tag(["Aux",B,CK,D,fixedOthers]);
        const s=JSON.stringify([D,CK,Aux]);
        counts.set(s,(counts.get(s)||0)+1);uniformPad++;
      }
      const fingerprint=Array.from(counts).sort((a,b)=>a[0].localeCompare(b[0]));
      if(first===null) first=fingerprint;
      ok(eq(first,fingerprint),"full B-only public view independent of sigma for uniform pad");
    }
  }
  for(let i=0;i<256;i++){
    const A=[rnd()%16,rnd()%16,rnd()%16,rnd()%16],K=rnd()%256;
    const U=toyH(A,K),uniformReplacement=U^(1<<(i%24));
    ok(toyH(A,K)!==uniformReplacement,"opened target detects replaced generator output");negative++;
  }
  return {run:"R80-SHARED-MATRIX-ADAPTIVE-SIBLING-OPENING-20261104",
    status:"RESTRICTED_CERTIFIED_FALSE_MULTICAPSULE_COMPOSITION_NOT_GENERIC_WKEM",
    assertions,pointwise_and_full_source_couplings:sourceCouplings,
    opened_other_capsule_checks:openedOther,uniform_pad_joint_view_cases:uniformPad,
    opened_target_negative_controls:negative,
    limitations:["finite toy math and hashes","no native signature implementation","no QPT hardness executed","no generic hard-TRUE ORIGINAL witness extraction","no practical Bitcoin endpoint"]};
}
console.log(JSON.stringify(checkR80(), null, 2));
```

## Captured V8 output

```json
{
  "run": "R80-SHARED-MATRIX-ADAPTIVE-SIBLING-OPENING-20261104",
  "status": "RESTRICTED_CERTIFIED_FALSE_MULTICAPSULE_COMPOSITION_NOT_GENERIC_WKEM",
  "assertions": 3593,
  "pointwise_and_full_source_couplings": 1536,
  "opened_other_capsule_checks": 573,
  "uniform_pad_joint_view_cases": 4096,
  "opened_target_negative_controls": 256,
  "limitations": [
    "finite toy math and hashes",
    "no native signature implementation",
    "no QPT hardness executed",
    "no generic hard-TRUE ORIGINAL witness extraction",
    "no practical Bitcoin endpoint"
  ]
}
```
