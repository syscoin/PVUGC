# R72 — GF(4) ternary commitment for the LWE honest-verifier pre-funding audit

**Status:** A provable 50% reduction in R71's *restricted* source-WELLFORMED 3-color proof commitment size, using the same ordinary-QPT-LWE premise and all existing honest-verifier restrictions. This is **not** generic-NP witness encryption, an ORIGINAL extraction theorem, arbitrary-FALSE security, a practical preflight, or deployed Bitcoin PQ functionality.

**Provenance:** R72-GF4-TERNARY-THREECOLOR-20261104; offline, 2026-11-04; verified open/draft/unmerged syscoin/PVUGC#1 branch research/pq-wkem-validation-20260918 starting at 4c0dad1ac47c90970f1d06894035ac045d9ac0f5. R71 exact blob 366eb05d42e423d997bd1def6cfcb4563040ea86, R70 exact blob de21beb69dd34fae508ff5917ddd52108f6118ad; latest ordinary substantive comment 6643346960. No web or external literature was used.

## Explicit missing requirement and new release-side component

R70/71 commit **two separate bits** for each three-color vertex, even though 11 is invalid. This run replaces them with **one direct ternary color commitment** while preserving the same graph preflight's proof soundness, honest-verifier privacy and the ability to embed an ACTUAL source QPT LWE challenge in the *entire* public-output simulation. It is an independent, reusable pre-funding audit efficiency advance, not a repair of the ORIGINAL source.

Retain R71's ordinary decisional QPT-LWE experiment: n; b=ceil(log2 n); q=2^(4b); m=4n; chi uniform signed b-bit errors; uniform A_com in Z_q^(m x n), uniform z in Z_q^n, independent chi error e, with Y either Az+e mod q or uniform. A nonuniform QPT distinguisher receives (A,Y), the complete public classical view, and auxiliary quantum/classical advice **independent of challenged hidden seed coins**. Its distinguishing advantage is epsilon_LWE. No reduction/calibration establishes 128-bit QPT hardness for this specific chi and n=128 toy sizing.

Let ell=8nb. Parse an ell-bit seed exactly into z and e, giving the classical-PPT generator G_A(s)=binary(Az+e mod q) of length 2ell. Define H_A(s0) via G_A(s0)=s1||b1, G_A(s1)=s2||b2, H_A(s0)=b1||b2||prefix_(2tau)(s2), of **even** length L=2ell+2tau, tau<=ell/2. Two straight-line ordinary-QPT-LWE hybrids give QPT PRG advantage at most 2 epsilon_LWE. All source matrices, root coins and native-signature keys are independent of A_com and these PRG seeds.

Interpret the L-bit output as L/2 field elements in GF(4)=F2[omega]/(omega^2+omega+1). For colors c=0,1,2 set distinct field scalars a_c=0,1,omega. After freezing public A_com, the honest pre-funding verifier samples a **single UNFILTERED uniform independent** R in GF(4)^(L/2), which may be public and reused across vertices, rounds and correctly scoped certificates. The classical-PPT prover samples a fresh independent ell-bit seed s per color and publishes

    Com_R(c;s) = H_A(s) + a_c * R.

The addition is XOR. Opening reveals (c,s), and Verify checks 0<=c<=2 and exact equality. For the canonical bit-pair encoding (a,b) representing a+b*omega, omega acts as (a,b)->(b,a+b), and omega^3=1. The three color offsets are 0, R, omega R; thus only **one** public challenge vector and ONE L-bit commitment per vertex are necessary.

## Lemma 1: unconditional simultaneous three-color binding

Fix *arbitrary* A_com and hence deterministic H_A. Set D={H_A(s)+H_A(s') for all seeds s,s'}, with |D|<=2^(2ell). If one published word opens to two different colors c!=d then (a_c-a_d)R belongs to D. For every unordered pair among three colors, (a_c-a_d) is nonzero in GF(4), so multiplication by it is a bijection on uniform R. A union over all three color-pairs gives the EXACT safe bound

    Pr_unfiltered_R[any two different-color openings exist]
       <= 3*2^(2ell-L) = 3*2^(-2tau).

This binds *all* commitments sharing R at once, not merely an isolated sample, for arbitrary quantum computation yielding classical openings. No hash/CRH assumption or quantum extraction is needed for this statistical statement. The finite checker tests a sampled good toy R for correctness only; **the honest construction never filters R or conditions its soundness theorem on a secretly checked good R**.

For a falsely asserted WELLFORMED source, let its publicly fixed 3-color graph have M edges. Outside that globally bad R event, any fixed committed coloring violates at least one edge. With t independent authenticated honest edges chosen **after** each complete commitment, QPT or unbounded malicious prover acceptance is bounded by (1-1/M)^t (classical commitments/openings). For Q pre-funding attempts with the same public R, a safe bound is 3*2^(-2tau) + Q*(1-1/M)^t. This is WELLFORMED preflight source-consistency soundness; it does NOT prove the original SYS/BTC witness relation, its false-instance security, or accepted key-recovery extraction.

## Lemma 2: QPT hiding and entire-public-view simulation

For any two colors c,d and any fixed public R, replacing H_A(U_ell) by U_L makes both commitments identically uniform. The two source-free, straight-line QPT-LWE generator hybrids therefore bound distinguishing between commitments to any two colors by 4 epsilon_LWE. For T fresh independent commitments, a coherent nonuniform QPT adversary processing all their classical ciphertexts, witness-hiding graph transcript, source C, Dsig, CK, Aux, contextual manifest and allowed independent related capsules suffers at most 4T epsilon_LWE from this replacement. Public R, A_com, native verification keys and the graph itself may be fully known, and hostile parties may perform adaptive *post*-commitment computation. A target that has been legitimately opened cannot be required to stay secret. No quantum rewinding, QROM extraction or corrupted-seed-dependent advice is invoked.

An honest 3-color prover permutes any valid coloring uniformly and commits with independent fresh seeds before an honest party selects an independently random edge. The verifier opens just the two endpoints. The straight-line honest-verifier simulator may choose the edge first, draw its two distinct endpoint colors uniformly, fill other vertex colors arbitrarily, then commit. Permuted genuine endpoint colors have exactly that ordered distinct-color distribution, while the unopened colors are computationally hidden by the QPT hybrids. A secretly chosen active-verifier challenge, malicious verifier controlling edge randomness, Fiat-Shamir in the QROM, and adversarial selective target openings are **not** established.

For the protected honest R69 source, the reduction embeds an ACTUAL (A_src,Y*) decisional QPT-LWE challenge as C_j=Round_q_to_p(Y*_j+Delta*mu_j*e0). It chooses K, precommitted native sigma, checking-key seed and permitted independent related setup coins itself, then recomputes Dsig, CK, Aux and exact frozen Base for the challenging source sample. It programs the honest-verifier 3-color certificate via the above simulator, using the independent public A_com and R. Source sample correlations, intended native vk, UTXO/claim, relation identity, branch, anchors/window, other capsules and auxiliary outputs are part of the *same* classical QPT input. This is a restricted simulator for the SIS-source WELLFORMED audit only; there is no SourceOpen oracle, unknown challenge z/e access, adversary-supplied representation or classical rewinding. The malicious-participant restrictions and static protection of one honest N-of-N slot from R69/R70 still apply.

## Exact costs and limitations

Using only R71's deliberately INSECURE illustrative n=128, b=7, m=512, ell=7168, tau=128, L=14592, a ternary commitment is 1,824 bytes, versus 3,648 bytes for R71's two bit commitments per vertex. The number of independently generated PRG seeds and H_A expansions also halves for vertex color commitments. For V=M=100,000, Q=2^20 and t=10,258,579 repeats, the original commitments require 3,742,329,619,200,000 bytes, versus **1,871,164,809,600,000 bytes** here. These are only commitments, excluding graph, transport, source, openings and signatures. **This remains ~1.87 PB and is not practical.**

The checker below executes the exact toy GF(4) operations, derives the finite global bad-R set, tests all 196,608 ordered seed/color-pair combinations for a sampled UNFILTERED good R (no selection filtering), checks 128 valid and 128 edge-programmed false-graph transcripts plus all 81 K4 colorings, and tests 128 whole-source LWE/uniform Y-to-C public CK/Aux/signature/related-view recomputations. No generic NP-to-3COLOR compiler, post-quantum signature, QPT attack, formal QPT LWE parameter analysis or Bitcoin path is tested.

**Decisive open equation:** generic classical-PPT compiler of ORIGINAL x must preserve Open(x,w)->the SAME precommitted K for EVERY valid ORIGINAL witness and derive, for arbitrary nonuniform QPT final-capability recovery/accepted native forgery, an actual ORIGINAL witness or independently justified QPT break in the complete original/full checking-key/auxiliary/multiple-capsule distribution. R58 public quotient trace and R63/R67 signed kernels still break the prior generic carriers. No generic security, arbitrary-FALSE result, malicious N-of-N abort/completeness, qualified 128-bit PQ params or Bitcoin-native PQ endpoint has been established. Keep the research automation enabled.

## Appendix A — exact executed connected V8 checker

```javascript
function checkR72(){
  let s=0x721104,assertions=0;
  const rng=()=>{s^=s<<13;s^=s>>>17;s^=s<<5;return s>>>0;};
  const ok=(v,m)=>{assertions++;if(!v)throw Error("assert "+assertions+": "+m);};
  const A=[1,5,11,13],ell=8,tau=4,L=24,qToy=16, mask=(1<<L)-1;
  function G(seed){
    ok(seed>=0&&seed<256&&Number.isInteger(seed),"seed domain");
    const z=seed&15;let out=0;
    for(let i=0;i<4;i++)out|=((((A[i]*z+((seed>>>(4+i))&1)-1)%16+16)%16)<<(4*i));
    return out;
  }
  function H(seed){
    const p=G(seed),s1=p&255,b1=p>>>8;
    const q=G(s1),s2=q&255,b2=q>>>8;
    return b1|(b2<<8)|(s2<<16);
  }
  function omega(x){
    let y=0;
    for(let i=0;i<L;i+=2){
      const a=(x>>>i)&1,b=(x>>>(i+1))&1;
      y|=(b|((a^b)<<1))<<i;
    }
    return y>>>0;
  }
  for(let i=0;i<L;i++)ok(omega(omega(omega(1<<i)))===(1<<i),"omega^3=id");
  const outs=Array.from({length:256},(_,i)=>H(i)),bad=new Set();
  for(const a of outs)for(const b of outs){
    const d=a^b;bad.add(d);bad.add(omega(d));bad.add(omega(omega(d)));
  }
  ok(bad.size<=3*65536,"global 3-pair union bound");
  const R=rng()&mask;
  ok(!bad.has(R),"independent toy public challenge R (not filtered)");
  const offset=c=>c===0?0:c===1?R:omega(R);
  const com=(c,k)=>{ok(c>=0&&c<=2,"color domain");return H(k)^offset(c);};
  for(let u=0;u<256;u++)for(let v=0;v<256;v++){
    ok(com(0,u)!==com(1,v),"no 0/1 equivocation");
    ok(com(0,u)!==com(2,v),"no 0/2 equivocation");
    ok(com(1,u)!==com(2,v),"no 1/2 equivocation");
  }
  const tri=[[0,1],[1,2],[2,0]], K4=[[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]];
  function perm(){
    const a=[0,1,2];for(let i=2;i>0;i--){let j=rng()%(i+1);[a[i],a[j]]=[a[j],a[i]];}return a;
  }
  function proof(graph,truth){
    const edge=rng()%graph.length,[u,v]=graph[edge],n=1+Math.max(...graph.flat());
    const p=perm(),colors=truth?truth.map(c=>p[c]):Array.from({length:n},(_,i)=>i===u?p[0]:i===v?p[1]:0);
    const seeds=colors.map(()=>rng()&255);
    const C=colors.map((c,i)=>com(c,seeds[i]));
    return {edge,C,open:[[colors[u],seeds[u]],[colors[v],seeds[v]]]};
  }
  function verify(graph,t){
    if(t.edge<0||t.edge>=graph.length)return false;
    const [u,v]=graph[t.edge],[[cu,su],[cv,sv]]=t.open;
    return cu!==cv&&[cu,cv].every(c=>c>=0&&c<3)
      &&t.C[u]===com(cu,su)&&t.C[v]===com(cv,sv);
  }
  for(let i=0;i<128;i++){
    const h=proof(tri,[0,1,2]),f=proof(K4,null);
    ok(verify(tri,h),"true graph accepts");
    ok(verify(K4,f),"programmed false simulator accepts");
    const t={...h,open:[[...h.open[0]],[h.open[0][0],h.open[1][1]]]};
    ok(!verify(tri,t),"equal colors rejected");
  }
  let falseAssignments=0;
  for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++){
    const x=[a,b,c,d];ok(K4.some(([u,v])=>x[u]===x[v]),"K4 no coloring");falseAssignments++;
  }
  function hash(x){
    let h=2166136261>>>0;
    for(const ch of JSON.stringify(x))h=Math.imul(h^ch.charCodeAt(0),16777619)>>>0;
    return h.toString(16);
  }
  let couplings=0;
  for(const mode of ["lwe","uniform"])for(let k=0;k<64;k++){
    const A_src=Array.from({length:8},()=>[rng()%65536,rng()%65536]);
    const z=[rng()%65536,rng()%65536],root=Array.from({length:4},()=>rng()%16);
    const Y=root.map(()=>A_src.map(row=>mode==="lwe"?
        (row[0]*z[0]+row[1]*z[1]+[-1,0,1][rng()%3])%65536:rng()%65536));
    const manifest={original:"restricted SIS",relid:"toy",outpoint:"txid:0",branch:"challenge",
      anchors:"bound",window:"frozen",verification_key:"vk_h",A_src,A_com:A,R,
      related:["independent claim"]};
    const cert=proof(mode==="lwe"?tri:K4,mode==="lwe"?[0,1,2]:null);
    ok(verify(mode==="lwe"?tri:K4,cert),"public verifier cert");
    const make=ys=>{
      const C=ys.map((row,j)=>row.map((y,i)=>(y+(i===0?192*root[j]:0))%65536));
      const base={manifest,C,Dsig:hash(["signature pad",root,manifest])};
      const CK=hash(["CK",root,base]),Aux=hash(["AUX",root,CK,base]);
      return {base,CK,Aux,cert,related:hash(["sibling",manifest])};
    };
    const a=make(Y),b=make(Y.map(t=>t.slice()));
    ok(JSON.stringify(a)===JSON.stringify(b),"joint public view");
    ok(hash(a)===hash(b),"coherent joint transcript bytes");couplings++;
  }
  const n=128,m=512,b=7,tauActual=128,ellActual=n*4*b+m*b,Lactual=2*ellActual+2*tauActual,V=100000,t=10258579;
  const old=2*V*t*Lactual/8,newSize=V*t*Lactual/8;
  ok(ellActual===7168&&Lactual===14592&&old===3742329619200000&&newSize===1871164809600000,"exact illustrative costs");
  return {run:"R72-GF4-TERNARY-THREECOLOR-20261104",status:"RESTRICTED_PREFLIGHT_50_PERCENT_SAVING_NOT_GENERIC_WKEM",
    assertions,toy_DifferenceBadR:bad.size,toy_space:1<<L,unfiltered_R:R,
    cross_color_seed_pairs:3*65536,honest_true_transcripts:128,
    programmed_false_transcripts:128,false_K4_colorings:falseAssignments,
    exact_full_joint_source_couplings:couplings,per_vertex_old_bytes:Lactual/4,
    per_vertex_new_bytes:Lactual/8,old_total_bytes:old,new_total_bytes:newSize,
    limitations:"Toy, QPT LWE not tested; no ORIGINAL extraction; no practical preflight/native PQ deployment"};
}
console.log(JSON.stringify(checkR72(), null, 2));
```

## Appendix B — captured output of that exact checker

```json
{
  "run": "R72-GF4-TERNARY-THREECOLOR-20261104",
  "status": "RESTRICTED_PREFLIGHT_50_PERCENT_SAVING_NOT_GENERIC_WKEM",
  "assertions": 1383980,
  "toy_DifferenceBadR": 50743,
  "toy_space": 16777216,
  "unfiltered_R": 308621,
  "cross_color_seed_pairs": 196608,
  "honest_true_transcripts": 128,
  "programmed_false_transcripts": 128,
  "false_K4_colorings": 81,
  "exact_full_joint_source_couplings": 128,
  "per_vertex_old_bytes": 3648,
  "per_vertex_new_bytes": 1824,
  "old_total_bytes": 3742329619200000,
  "new_total_bytes": 1871164809600000,
  "limitations": "Toy, QPT LWE not tested; no ORIGINAL extraction; no practical preflight/native PQ deployment"
}
```
