# R71 — Ordinary QPT-LWE instantiates R70's off-chain preflight PRG

**Actual constructive delta, not a generic witness-KEM:** R70 separately assumed a QPT-secure pseudorandom generator for its classical-PPT honest-verifier capsule-consistency certificate. Here that generator is explicitly realized from the same independently defined ordinary decisional-QPT-LWE experiment already required for the restricted R69 source. The release-to-ORIGINAL witness theorem, arbitrary-FALSE security and practical off-chain proof remain UNSOLVED.

**Provenance:** R71-LWE-PRG-HV-PREFLIGHT-20261104, offline, 2026-11-04, starting from open/draft/unmerged PVUGC PR #1 head 7ba5ffedd987c147608baa278e8fb436c64991b0 on research/pq-wkem-validation-20260918. Exact predecessor read: research/pq-wkem/r70_honest_challenge_preflight_20261104/RESEARCH_AND_CHECKER.md, Git blob de21beb69dd34fae508ff5917ddd52108f6118ad; latest substantive ordinary comment 6641778978. No web or external literature.

## Exact generator and independently stated QPT assumption

At dimension n, let b=ceil(log2 n), q=2^(4b), m=4n, and chi be uniform over signed b-bit integers in [-2^(b-1),2^(b-1)-1]. The QPT decisional LWE challenge draws A uniform in Z_q^(m x n), secret z uniform in Z_q^n, and e from independent chi coordinates. A QPT distinguisher receives classical (A,Y), with Y either Az+e mod q or uniform Z_q^m, and independent classical/quantum auxiliary input. Define its maximum advantage epsilon_LWE. This is an independently meaningful standard *form* of an ordinary QPT-LWE assumption, not a proved hardness reduction for this exact bounded-uniform chi or a verified 128-bit parameter claim. The adversary can coherently evaluate the public generator, but advice correlated with challenged hidden z/e or generator seed is excluded.

The protected honest off-chain verifier chooses an independent uniform public A_com, not a R69 source matrix. A uniform seed s of ell=n*4b+m*b=8nb bits deterministically parses into exactly uniform z (n canonical 4b-bit blocks) and independent signed errors e (m canonical b-bit blocks offset by 2^(b-1)). Define G_A(s)=binary encoding of Az+e mod q, using 4b bits per coordinate. The output length is m*4b=16nb=2ell. The distribution of (A,G_A(U_ell)) is exactly the stated ordinary LWE distribution, so one straight-line QPT challenge distinguishes it from (A,U_2ell) with advantage at most epsilon_LWE.

For statistical target tau<=ell/2, iterate the same public-A generator twice: G_A(s0)=s1||b1 and G_A(s1)=s2||b2, where all halves have ell bits. Define H_A(s0)=b1||b2||prefix_(2tau)(s2), length L=2ell+2tau. Two sequential hybrids first replace G_A(s0) with uniform, then G_A(s1) with uniform after s1 is independent; both are genuine single-sample ordinary QPT-LWE reductions with the same public A. Thus H_A(U_ell) differs from uniform L bits by at most 2 epsilon_LWE. No source-opening oracle, quantum rewinding, ideal model, or witness-releasing assumption is used.

After A_com is frozen, the honest verifier draws uniform independent R in {0,1}^L. Bit commitment is Com_(A,R)(bit;s)=H_A(s) XOR (bit*R), with fresh independent uniform ell-bit s. For every fixed A, the set of R admitting opposite-bit openings is contained in the at most 2^(2ell) differences H_A(s) XOR H_A(s'). Therefore even unbounded-prover equivocation has probability <=2^(-2tau) over the honest independent R. For honestly uniform A_com, QPT committed-bit distinguishing advantage is <=4 epsilon_LWE through the uniform L-bit hybrid. T independent-seed commitments to adaptively chosen bits cost at most 4T epsilon_LWE, even with arbitrary coherent processing of the complete classical public view, provided the target opening coins are not part of auxiliary advice. A_com and R may be reused, but individual s must not be reused.

## Full-public-view reduction and limits

Retain the frozen claim/UTXO, ORIGINAL relation identity, branch/anchor/window, source matrices, native intended verification key/capability, source capsule, Dsig, checking key, auxiliary data and related-capsule references from R69/R70. WELLFORMED privately witnesses root K, source z/e and the native pre-signature, and checks source rounding, Dsig, CK, Aux and signature against exact intended challenge path. This is a *source-consistency* witness, not automatically the ORIGINAL evidence required by generic SYS/BTC.

For R70's off-chain 3COLOR certificate, commit two bits for each vertex independently. Send all commitments before the honest verifier chooses its independently uniform random edge; open its two endpoints. In the LWE source-hybrid simulator, embed actual (A_src,Y*) from a QPT LWE challenge into C*=Round(Y*+Delta*mu*e0); the simulator knows its own K and native signature but **does not know** the challenged z/e. Recompute all Base/Dsig/CK/Aux and independently permitted related capsule outputs jointly, then use the honest-verifier proof simulator: sample the verifier's unpredictable edge in advance, assign distinct uniform random colors to endpoints, arbitrary colors elsewhere, and open only the endpoints. On a real well-formed source, the opened endpoint colors match exactly those of a random permutation of a valid graph coloring. Every unopened bit commitment is computationally hidden by the explicit generator above. This proof simulator is straight-line and has **no** requirement to supply source z/e, representation or ORIGINAL witness.

For graph vertex count V and t repetitions, a coarse QPT transcript-hybrid cost is <=8tV epsilon_LWE, summed across separately generated certificates and permissible independent related claims. On source-uniform hybrids the simulated certificate may pass a FALSE WELLFORMED graph: this is permitted *inside the simulator*, not a valid real-world prover strategy, because actual honest verifier challenges arrive only after the commitments. For <=Q bounded adaptive attempts and M graph edges per false graph, R70's real-world classical-message QPT proof soundness remains <=Q*2^(-2tau)+Q*(1-1/M)^t. It needs honest unguessable edge randomness, classical messages, a fixed graph and binding source commitments. It does not establish malicious-verifier zero knowledge, full quantum proof extraction, Fiat-Shamir or random-oracle QPT security. Static protection of the honest N-of-N slot, no graph bypass, safe abort/DA and exact related-capsule opening policy remain assumptions. A timely admissible challenge/Bitcoin endpoint still require the separately specified conditional native graph.

## Exact resource calculation and limitations

Illustrative, NOT QPT-security-calibrated n=128, m=512, b=7, q=2^28, chi uniform [-64,63] yields ell=7168 bits, G output=14336 bits, H output=14592 bits at statistical tau=128. A single bit commitment is 1824 bytes; reusable public A_com is 229376 bytes packed. For the R70 illustrative graph V=100000 and 10258579 repetitions, two commitments per vertex require 3742329619200000 bytes (3.742 PB) before graph/transport/verification overhead. This instantiation *removes a free security assumption* but is emphatically NOT PRACTICAL. Statistical tau=128 is not 128-bit QPT-LWE hardness.

The exact JS checker below is executed in the same connected V8 environment used to publish this file; its captured result follows it. It enumerates all 256 toy generator seeds, all 65536 opposite-bit opening pairs, 128 honest TRUE and 128 honestly programmed FALSE 3COLOR transcripts, K4's 81 colorings, and 128 full correlated source/CK/Aux/related public-view challenge couplings. This is an illustrative finite mathematical test with insecure PRNG and toy hashing; it does not implement NP-to-3COLOR, native SLH, QPT attacks, malicious-verifier ZK or generic ORIGINAL recovery. A separate local Python checker ran twice identically with 363993 assertions; its files are local-only, not represented as this GitHub checker.

## Next indispensable missing equation

R58's public-quotient bypass and R63/R67's signed-kernel recovery remain unpatched. Neither source consistency nor accepted internal representation proves that arbitrary key recovery/native forgery yields an ACTUAL ORIGINAL witness. A complete classical-PPT generic-original source compiler must satisfy every-witness same-precommitted-capability correctness, and its FULL public distribution (x, C, CK, Aux, scope, related capsules, openings) must admit an independently justified straight-line QPT simulator together with:

Pr[QPT adversary obtains intended native capability] <= Pr[R_ORIGINAL(x, Ext^adversary(full view))=1] + Adv_independent_QPT + negligible(n).

This equation is NOT proved here. Arbitrary-FALSE, hard-TRUE, malicious N-of-N completeness, practical resources and the hypothetical Bitcoin PQ endpoint remain open. The research automation must remain enabled.

## Appendix A — Exact executed V8 checker


```javascript
function checkR71(){
  let seed=0x711104, assertions=0, couplings=0;
  const random=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;};
  const ok=(v,msg)=>{assertions++;if(!v)throw Error("assert "+assertions+": "+msg);};
  const A=[1,5,11,13], ell=8;
  function G(s){
    ok(Number.isInteger(s)&&s>=0&&s<256,"seed");
    const z=s&15;let y=0;
    for(let i=0;i<4;i++){
      const e=((s>>>(4+i))&1)-1;
      const v=((A[i]*z+e)%16+16)%16;
      y|=v<<(4*i);
    }
    return y;
  }
  function H(s){
    const y1=G(s),s1=y1&255,b1=y1>>>8;
    const y2=G(s1),s2=y2&255,b2=y2>>>8;
    return b1|(b2<<8)|(s2<<16);
  }
  const outputs=Array.from({length:256},(_,s)=>H(s)),D=new Set();
  for(const u of outputs)for(const v of outputs)D.add(u^v);
  ok(D.size<=65536,"difference set");
  let R=1<<20;while(D.has(R))R++;
  ok(R<(1<<24),"R outside bad set");
  const com=(b,s)=>H(s)^(b?R:0);
  for(let s=0;s<256;s++)for(let t=0;t<256;t++)ok(com(0,s)!==com(1,t),"statistical bit binding");
  for(let s=0;s<256;s++){
    const z=s&15;let expected=0;
    for(let i=0;i<4;i++)expected|=(((A[i]*z+((s>>>(4+i))&1)-1)%16+16)%16)<<(4*i);
    ok(G(s)===expected,"exact q-LWE sample");
  }
  const tri=[[0,1],[1,2],[2,0]],k4=[[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]];
  function perm(){
    const p=[0,1,2];for(let i=2;i>0;i--){const j=random()%(i+1);[p[i],p[j]]=[p[j],p[i]];}return p;
  }
  function color(c){
    const r=[random()&255,random()&255];
    return {c:[com((c>>>1)&1,r[0]),com(c&1,r[1])],r};
  }
  function transcript(g,truth=null){
    const e=random()%g.length,[u,v]=g[e],p=perm();
    const colors=truth?truth.map(c=>p[c]):
      Array.from({length:Math.max(...g.flat())+1},(_,j)=>j===u?p[0]:j===v?p[1]:0);
    const vtx=colors.map(color);
    return {e,c:vtx.map(x=>x.c),reply:[colors[u],colors[v],vtx[u].r,vtx[v].r]};
  }
  function verify(g,t){
    const [u,v]=g[t.e],[a,b,ra,rb]=t.reply;
    if(a===b||![0,1,2].includes(a)||![0,1,2].includes(b))return false;
    return JSON.stringify(t.c[u])===JSON.stringify([com((a>>>1)&1,ra[0]),com(a&1,ra[1])])
        && JSON.stringify(t.c[v])===JSON.stringify([com((b>>>1)&1,rb[0]),com(b&1,rb[1])]);
  }
  for(let i=0;i<128;i++){
    ok(verify(tri,transcript(tri,[0,1,2])),"honest 3color");
    ok(verify(k4,transcript(k4)),"witnessless simulated 3color with programmed honest challenge");
  }
  for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++){
    const v=[a,b,c,d];ok(k4.some(([u,w])=>v[u]===v[w]),"non-3colorable K4");
  }
  const str=x=>JSON.stringify(x);
  function hash(x){
    let h=2166136261>>>0;
    for(const c of str(x))h=Math.imul(h^c.charCodeAt(0),16777619)>>>0;
    return h.toString(16);
  }
  for(const mode of ["lwe","uniform"])for(let r=0;r<64;r++){
    const A_src=Array.from({length:8},()=>[random()%65536,random()%65536]);
    const z=[random()%65536,random()%65536];
    const Y=A_src.map(row=>mode==="lwe"
      ?(row[0]*z[0]+row[1]*z[1]+[-1,0,1][random()%3]+65536)%65536
      :random()%65536);
    const root=[random()%16,random()%16,random()%16,random()%16];
    const V={original:"restricted SIS",claim:"outpoint:7",branch:"challenge",
      anchors:"fixed",verification_key:"vk_h",A_src,A_com:A,R,
      related:["independent claim"]};
    const assemble=ys=>{
      const C=root.map(w=>ys.map((y,i)=>(y+(i===0?192*w:0))%65536));
      const Base={V,C,Dsig:hash(["masked native signature",root,V])};
      const CK=hash(["ck",root,Base]),Aux=hash(["aux",root,CK,Base]);
      return {Base,CK,Aux,related:hash(["other claim",V])};
    };
    const source=assemble(Y),sim=assemble([...Y]);
    ok(str(source)===str(sim),"full correlated source view");
    const cert=transcript(mode==="lwe"?tri:k4);
    ok(verify(mode==="lwe"?tri:k4,cert),"public accepting honest programmed transcript");
    ok(hash([source,cert])===hash([sim,cert]),"exact full public bytes");
    couplings++;
  }
  const n=128,m=512,bq=28,be=7,tau=128,seedBits=n*bq+m*be;
  ok(seedBits===7168&&m*bq===14336,"formal seed and output lengths");
  const commitmentBits=2*seedBits+2*tau;
  ok(commitmentBits===14592,"formal commitment length");
  ok(100000*2*10258579*commitmentBits/8===3742329619200000,"formal cost");
  return {run:"R71-LWE-PRG-HV-PREFLIGHT-20261104",status:"RESTRICTED_LWE_PRG_INSTANTIATION_ONLY",
    assertions,enumerated_seeds:256,toy_difference_set_size:D.size,
    all_opposite_bit_pairs_checked:65536,
    true_proofs:128,simulated_false_proofs:128,full_public_view_couplings:couplings,
    parameters:{n,m,q_bits:bq,error_bits:be,seed_bits:seedBits,
      base_output_bits:14336,commitment_bits:commitmentBits,
      per_bit_bytes:commitmentBits/8,public_matrix_bytes:m*n*bq/8,
      total_commitment_bytes:3742329619200000},
    limitations:["Toy, insecure; QPT LWE not tested","No generic ORIGINAL witness extraction",
      "No generic NP-to-3COLOR compiler executed","No real SLH signature",
      "No malicious verifier ZK or practical preflight"]};
}
console.log(JSON.stringify(checkR71(),null,2));
```

## Appendix B — Exact captured V8 output

```json
{
  "run": "R71-LWE-PRG-HV-PREFLIGHT-20261104",
  "status": "RESTRICTED_LWE_PRG_INSTANTIATION_ONLY",
  "assertions": 337878,
  "enumerated_seeds": 256,
  "toy_difference_set_size": 16960,
  "all_opposite_bit_pairs_checked": 65536,
  "true_proofs": 128,
  "simulated_false_proofs": 128,
  "full_public_view_couplings": 128,
  "parameters": {
    "n": 128,
    "m": 512,
    "q_bits": 28,
    "error_bits": 7,
    "seed_bits": 7168,
    "base_output_bits": 14336,
    "commitment_bits": 14592,
    "per_bit_bytes": 1824,
    "public_matrix_bytes": 229376,
    "total_commitment_bytes": 3742329619200000
  },
  "limitations": [
    "Toy, insecure; QPT LWE not tested",
    "No generic ORIGINAL witness extraction",
    "No generic NP-to-3COLOR compiler executed",
    "No real SLH signature",
    "No malicious verifier ZK or practical preflight"
  ]
}
```
