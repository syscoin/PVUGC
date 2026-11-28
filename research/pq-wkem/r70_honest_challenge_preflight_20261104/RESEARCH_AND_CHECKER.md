# R70 — Honest-challenge PQ capsule preflight (restricted composition)

**Status:** A new, explicitly specified off-chain **pre-funding consistency certificate** for R69's restricted independent-matrix SIS release. It is **not** a generic-NP witness-KEM, does **not** prove hard-TRUE recovery-to-ORIGINAL-witness extraction, and is not remotely practical at large generic-NP circuit sizes. Mathematical claims below are conditional on an independently QPT-secure PRG and the already restricted R69 model. The checked cryptographic fixtures are deliberately insecure.

**Provenance:** run R70-HONEST-CHALLENGE-PREFLIGHT-20261104, 2026-11-04. Verified PVUGC PR #1 (open/draft/unmerged), branch `research/pq-wkem-validation-20260918`, starting SHA `12c1c52b1022641b249461a8585df49050576061`. R69 research exact blob `01f91fceb0133fe3a2d2f0ecc4fcfb9a97202141`; most recent substantive ordinary comment `6640555425`. Offline mathematical derivation/check; no web or external literature.

## Missing R69 requirement and actual construction

R69 has the all-witness release equation but corrupt signers may publish malformed ciphertexts, root/checking-key mismatches or a nonexistent native pre-signature, denying challenge liveness **after** funding. Before irreversible funding, freeze the complete claim/UTXO, ORIGINAL-relation identity, branch, anchors/window, all matrices and parameter identities, ordered native verification keys, pre-signed challenge message m*(V), no-bypass N-of-N graph, public scope, data availability, and exact related-capsule references in immutable manifest V. Do not hash the source capsule into the very sighash message that is required to create it.

For each signer j the public NP statement y_j is (V, A_j, all rounded C_j, masked native signature Dsig_j, CK_j, Aux_j, vk_j, exact Base_j, declared related capsules). The private witness is root K_j, exact native signature sigma_j and each source (z_{j,t},e_{j,t}). Verify off-chain, inside **WELLFORMED(y_j,w_j)**:

* K_j is parsed into B=16 distinct 16-bit words mu_t; e_{t,i} is bounded by the declared E; each public word satisfies Ctilde_{j,t}=Round_{q->p}(A_j z_{j,t}+e_{j,t}+Delta mu_t e0) with exact signed representative, arithmetic and rounding conventions.
* Verify(vk_j,m*(V),sigma_j)=1 for the exact intended native signature rule; derive (S_j,Kbind_j)=G_full(K_j); require Dsig_j=sigma_j XOR TreeG(S_j), CK_j=F_Kbind_j("CK",Base_j), Aux_j=F_Kbind_j("AUX",CK_j,Base_j).
* Base_j includes the immutable V, ordered slots, ciphertext and masked-signature bytes, source and branch metadata, and all related identities without cyclic hashes; reject inconsistent scope, mismatched public outputs and unavailable signed resources.

A fixed deterministic polynomial-time NP-to-3COLOR compiler maps WELLFORMED to graph H_j=(vertices,edges) and a valid witness to a coloring. That generic compiler is a standard combinatorial theorem, **not implemented by the published toy checker**. Bitcoin does not verify this graph, the proof, the original relation, or any PCP/VM/BitVM trace.

## Classical-PPT honest-challenge interactive proof; quantum-aware model

Take a QPT-secure, classical-PPT PRG G:{0,1}^lambda->{0,1}^{4lambda}, whose concrete QPT reduction/parameters must be supplied separately from an ordinary-LWE construction. One protected honest pre-funding verifier samples uniform R in {0,1}^{4lambda}. Bit commitment is Com_R(b;s)=G(s) XOR (b*R), independently fresh s of lambda bits. With D={G(s) XOR G(s')}, Pr[R in D]<=2^{-2lambda}; outside D, even an unbounded prover cannot open one commitment both ways. For any fixed fresh uniform R, a single hidden bit is QPT-hiding up to 2 Adv_QPT-PRG, by two hybrids through uniform. Independent coins are required per bit.

In each of t rounds the prover samples a fresh uniform permutation of an actual coloring, commits all two-bit vertex colors (00,01,10; 11 invalid), and **sends all commitments first**. The honest verifier then selects an independent uniform graph edge e, authenticates the previously received commitment digest and its signed edge challenge, and demands the two endpoint openings. Accept only if both open to distinct valid colors. Every participant must have an accepted signed certificate for every intended slot before broadcasting the irreversible funding transaction. The one honest participant issues its own challenges for all malicious slots; it can self-audit its own honest slot. Aborted/failed attempts are not funding authorization.

For a false WELLFORMED statement, the resulting graph is not 3-colorable. Conditioned on good R, every fixed committed coloring violates at least one edge, so for M=|edges| the per-round acceptance probability, even against an arbitrary QPT prover producing classical messages and keeping quantum workspace, is at most 1-1/M. Independent honest challenges imply
```
Pr[accept false statement] <= 2^(-2lambda) + (1-1/M)^t
                            <= 2^(-2lambda) + exp(-t/M).
```
For at most Q adaptive claim-specific attempts and a declared maximum M_max, require t >= ceil(M_max*(lambda*ln(2)+ln(Q))); unconditional chance that any false attempt is accepted is <= Q*2^(-2lambda)+2^(-lambda). Selective abort causes only no-funding; unlimited retries invalidate the bound. Acceptance proves **existence** of a well-formed hidden source and real native signature, not uniform source randomness, ORIGINAL x truth, efficient source-witness discovery or knowledge extraction from arbitrary attackers. Corrupt A_j may still make the common SIS witness intersection empty.

## Straight-line joint-view simulator; no SourceOpen

Given only public y_j and an honest verifier's truly independent edge randomness, a classical-PPT simulator generates an **accepting** proof transcript without any source secrets: for each round it samples an edge e itself, selects two uniformly random distinct endpoint colors, makes honest commitments to those two colors and fixed-zero commitments elsewhere, and opens only the endpoints. It may do this even if y_j is FALSE. For a real honest coloring randomly permuted each round the two opened colors have precisely the same uniform ordered-distinct law. QPT-hiding of unopened commitments gives a coarse joint transcript distinguishing bound of 4*t*|vertices|*Adv_QPT-PRG. This is a straight-line *honest-challenge publicly replayed transcript* simulator, NOT a malicious-verifier general quantum zero-knowledge claim. Adaptive classical messages are allowed only if the corrupt participants cannot choose or predict the honest edge challenges, and honest verification coins/PRG seeds are fresh and independent of their quantum advice.

To simulate the FULL honest public source in the existing R69 ordinary-QPT-LWE word hybrid, take an actual challenge (A*,Y*) (Y*=A*z+e or uniform), publish A_h=A*, let hostile participants choose A_-h using A* **before** C_h is visible, freeze V, choose K_h and the intended actual honest pre-signature, and set Ctilde_(h,t*)=Round_q->p(Y*+Delta*mu_t*e0). Construct all other honest source words, Dsig, full Base, CK, Aux, related independently generated claims and malicious postprocessing **together**. The WELLFORMED graph for this public y_h is now known, but the simulator cannot know challenged z/e. Use the straight-line proof simulator for the honest certificate. First replace real honest transcripts by simulator output using QPT-PRG hiding; then switch actual ordinary LWE challenges. In the uniform branch the simulated transcript still verifies even when no WELLFORMED witness exists. This avoids SourceOpen and does not require the adversary to reveal a representation. For at most polynomially many proofs add their transcript-hiding losses to R69's **restricted** ordinary-QPT-LWE/whole-generator/native-EUF/binding bound. Target-witness-correlated auxiliary advice or an opening of the same honest target is excluded. This remains separate from recovery-to-ORIGINAL evidence.

## Resources, attack boundaries and next obligation

This simple ZK preflight is **not practical at large scale**. Each round commits 2 bits per vertex with 4lambda-bit commitments; hence lambda bytes per vertex per round. At lambda=128, graph vertices=edges=100,000 and Q=2^20, t=10,258,579, producing **about 131.31 TB of commitments** before challenges, openings, signatures or graph computation. These are untested illustrative graph sizes, not final engineering estimates. Replacing the protocol with a practical, independently QPT-sound/hiding efficient off-chain zero-knowledge proof is still necessary; do not invoke Fiat-Shamir, STARKs, SIS or generic extraction without a quantum-secure derivation.

R58's public quotient-trace bypass and R63/R67's signed-kernel attack remain intact. The core unproved inequality is
```
Pr[QPT adversary obtains intended native capability from ALL public outputs]
<= Pr[R_ORIGINAL(x, Ext^A(full view)) = 1]
   + Adv_independent_QPT_break + negl(lambda).
```
This must yield an ACTUAL ORIGINAL witness or an independent PQ break without an adversary-supplied representation. Arbitrary-FALSE and hard-TRUE generic-NP security, practical parameters, setup liveness under hostile matrices, malicious abort, and the hypothetical Bitcoin-native PQ endpoint remain unsolved. The user-requested completion/stopping criteria are NOT met.

## Executed verification and exact provenance

The JavaScript checker appended below was executed directly in the connected V8 environment. Its printed output is preserved verbatim. It tests mathematical toy binding disjointness, 160 honest 3-color transcripts, 160 simulated accepting K4 transcripts (only with programmed honest challenges), all 81 K4 three-colorings, and 96 source Y-to-rounded-C full-view constructions with correlated Dsig/CK/Aux. The actual local **independent** Python checker also passed 9,351 assertions and 96 source challenge couplings; it is not the published V8 source. The JS and Python toy hashes/PRGs are NOT cryptographically secure, neither implements the NP-to-3COLOR compiler or a QPT LWE proof, and no native SLH signature deployment or GitHub independent agent is claimed.

## Appendix A — EXACT executed V8 checker

```javascript
function checker() {
  let seed=0x70a1104, assertions=0;
  const rnd=()=>{seed^=seed<<13; seed^=seed>>>17; seed^=seed<<5;return seed>>>0;};
  const check=(yes,why)=>{assertions++;if(!yes)throw Error("assertion "+assertions+" "+why);};
  const lam=4,mask=(1<<(4*lam))-1;
  const G=s=>((Math.imul(s+7,0x9e37)^(s<<10)^((s*s)<<5)^(s*53))&mask);
  const D=new Set();
  for(let s=0;s<16;s++)for(let t=0;t<16;t++)D.add(G(s)^G(t));
  let R=0x1000;while(D.has(R))R++;
  check(D.size<=256 && !D.has(R),"binding difference set");
  const com=(b,s)=>(G(s)^(b?R:0));
  for(let s=0;s<16;s++)for(let t=0;t<16;t++)check(com(0,s)!==com(1,t),"statistical binding outside bad R");
  const bits=c=>[(c>>1)&1,c&1];
  const commitColor=c=>{
    const cs=[rnd()&15,rnd()&15],b=bits(c);
    return {c:[com(b[0],cs[0]),com(b[1],cs[1])],s:cs};
  };
  const tri=[[0,1],[1,2],[2,0]],K4=[[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]];
  const verify=(g,e,C,reply)=>{
    const [a,b]=g[e],[ca,cb,sa,sb]=reply;
    if(ca===cb||ca>2||cb>2||ca<0||cb<0)return false;
    for(const [v,color,seeds] of [[a,ca,sa],[b,cb,sb]]){
      const bb=bits(color);
      for(let j=0;j<2;j++)if(C[v].c[j]!==com(bb[j],seeds[j]))return false;
    }
    return true;
  };
  const shuffle=()=>{const p=[0,1,2];for(let i=2;i>0;i--){let j=rnd()%(i+1);[p[i],p[j]]=[p[j],p[i]];}return p;};
  const honest=(g,colors)=>{
    const p=shuffle(),data=colors.map(c=>commitColor(p[c]));
    const e=rnd()%g.length,[u,v]=g[e];
    return {e,C:data,reply:[p[colors[u]],p[colors[v]],data[u].s,data[v].s]};
  };
  const simulated=g=>{
    const e=rnd()%g.length,[u,v]=g[e],p=shuffle(),C=[];
    const n=Math.max(...g.flat())+1;
    for(let i=0;i<n;i++)C.push(commitColor(i===u?p[0]:i===v?p[1]:0));
    return {e,C,reply:[p[0],p[1],C[u].s,C[v].s]};
  };
  for(let i=0;i<160;i++){
    const h=honest(tri,[0,1,2]),s=simulated(K4);
    check(verify(tri,h.e,h.C,h.reply),"honest TRUE graph");
    check(verify(K4,s.e,s.C,s.reply),"simulated FALSE graph, honest challenge programmed");
    check(!verify(K4,s.e,s.C,[s.reply[0],s.reply[0],s.reply[2],s.reply[3]]),"tampered opening");
  }
  let maxGood=0,count=0;
  for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++){
    const v=[a,b,c,d];const good=K4.reduce((n,[i,j])=>n+(v[i]!==v[j]),0);
    maxGood=Math.max(maxGood,good);count++;
  }
  check(maxGood===5&&count===81,"K4 requires >=1 bad edge for each coloring");
  const hash=x=>{let t=2166136261>>>0;for(const ch of JSON.stringify(x)){t=Math.imul(t^ch.charCodeAt(0),16777619)>>>0;}return t.toString(16);};
  const q=65536,p=4096,ratio=q/p,Delta=ratio*12,m=8,n=2;
  const sampledA=()=>Array.from({length:m},()=>Array.from({length:n},()=>rnd()%q));
  const Yfrom=(A,mode)=>{
    if(mode==="uniform")return Array.from({length:m},()=>rnd()%q);
    const z=[rnd()%q,rnd()%q];
    return A.map(row=>(row[0]*z[0]+row[1]*z[1]+([-1,0,1][rnd()%3])+q)%q);
  };
  const fromChallenge=(Y,w)=>Y.map((v,i)=>(Math.floor(((v+(i===0?Delta*w:0))%q+ratio/2)/ratio))%p);
  let sourceCouplings=0;
  for(const mode of ["lwe","uniform"])for(let rep=0;rep<48;rep++){
    const A=sampledA();
    const Mal=Array.from({length:3},(_,j)=>A.map((row,i)=>row.map(v=>(v+(j+1)*31+i*7)%q)));
    const V={claim:"tx:vout",branch:"challenge",anchors:"fixed",matrices:[A,...Mal],nativeKeys:["h","c1","c2","c3"]};
    const K=[rnd()%16,rnd()%16,rnd()%16,rnd()%16];
    const Y=K.map(()=>Yfrom(A,mode));
    const assemble=(source,root)=>{
      const C=source.map((y,i)=>fromChallenge(y,root[i]));
      const Base={V,C,Dsig:hash(["masked-native-signature",root,V]),related:[hash(["separate-related",V])]};
      const CK=hash(["CK",root,Base]);const Aux=hash(["AUX",root,CK,Base]);
      return {Base,CK,Aux};
    };
    const actual=assemble(Y,K);
    // The simulator below receives only (A,Y) and K; it never receives source z/e.
    const simulatedSource=assemble(Y.map(v=>v.slice()),K);
    check(JSON.stringify(actual)===JSON.stringify(simulatedSource),"complete joint source CK Aux coupling");
    const proof=simulated(mode==="lwe"?tri:K4);
    check(verify(mode==="lwe"?tri:K4,proof.e,proof.C,proof.reply),"no-secret simulated preflight proof");
    check(hash({source:actual,proof})===hash({source:simulatedSource,proof}),"entire public view equality");
    check(hash(["AUX",K,"wrong",actual.Base])!==actual.Aux,"CK Aux tamper");
    sourceCouplings++;
  }
  return {run:"R70-HONEST-CHALLENGE-PREFLIGHT-20261104",result:"RESTRICTED_PRE_FUNDING_CERTIFICATE_NOT_GENERIC_WKEM",assertions, honest_true_transcripts:160, simulated_false_transcripts:160, full_joint_source_couplings:sourceCouplings, false_graph_colorings:count, false_graph_max_good_edges:maxGood, false_graph_edges:K4.length, toy_binding_bad_R_values:D.size, toy_binding_R_space:1<<(4*lam), limitations:["Toy PRG, not QPT secure","Graph is toy; no generic NP to 3color compiler executed","No QPT LWE proof executed","No real native PQ signature","No generic ORIGINAL-witness extraction","No quantum-active-verifier ZK"]};
}

console.log(JSON.stringify(checker(), null, 2));
```

## Appendix B — EXACT captured checker result

```json
{
  "run": "R70-HONEST-CHALLENGE-PREFLIGHT-20261104",
  "result": "RESTRICTED_PRE_FUNDING_CERTIFICATE_NOT_GENERIC_WKEM",
  "assertions": 1122,
  "honest_true_transcripts": 160,
  "simulated_false_transcripts": 160,
  "full_joint_source_couplings": 96,
  "false_graph_colorings": 81,
  "false_graph_max_good_edges": 5,
  "false_graph_edges": 6,
  "toy_binding_bad_R_values": 121,
  "toy_binding_R_space": 65536,
  "limitations": [
    "Toy PRG, not QPT secure",
    "Graph is toy; no generic NP to 3color compiler executed",
    "No QPT LWE proof executed",
    "No real native PQ signature",
    "No generic ORIGINAL-witness extraction",
    "No quantum-active-verifier ZK"
  ]
}
```
