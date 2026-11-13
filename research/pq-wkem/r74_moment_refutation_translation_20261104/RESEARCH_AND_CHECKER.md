# R74 — Exact moment-refutation source simulation (restricted FALSE full-view theorem)

Run R74-MOMENT-REFUTATION-TRANSLATION-20261104; STATUS: a new exact source and restricted conditional QPT whole-view theorem, NOT generic witness-KEM security. Offline only. Baseline PVUGC PR #1 branch research/pq-wkem-validation-20260918 head 4da69775a308909b69fa0efb1b036b222669d8c8. Precursors R73 exact blob 1bacc3e1fce9e6a28ffd6033e1d3a2bc3c90a2f8 and R71 exact blob 366eb05d42e423d997bd1def6cfcb4563040ea86.

## Build_x, Open_x and exact all-ORIGINAL-witness correctness

Compile a fully scope-bound ORIGINAL width-3 CNF F (relation identity, evidence, UTXO/claim, path/branch, anchors/window, native verification key). Over the Boolean quotient Z_q[X]/(X_i^2-X_i), with q a power of two, fix constant d>=3. Rows of public A_x correspond to all monomials X_S with |S|<=d, M=sum_{i<=d}choose(n,i). For each clause C put a column for every multilinear coefficient vector X_T f_C of degree <=d, where f_C is the product of (1-X_i) over positive literals and X_i over negative literals. Classical construction has D=O(|F|n^d) columns, M=O(n^d) rows at fixed d. EVERY satisfying ORIGINAL assignment w provides distinct r_w[S]=product of w_i (i in S), normalized r_w[empty]=1 and r_w^T A_x=0 exactly; no canonical state.

Build samples a precommitted uniformly random root K of length ell bits, symbols mu_j of b bits, fresh uniform z_j in Z_q^D and fresh bounded e_j in [-E,E]^M. It publishes C_j=Round_q_to_p(A_x z_j+e_j+Delta mu_j e_empty), with p|q, s=q/p, Delta=s Lambda. Every valid ORIGINAL witness recovers the same precommitted K because r_w^T C_j=Lambda mu_j+eta_j mod p and |eta_j|<=M(E/s+1/2), provided Lambda>2M(E/s+1/2) and p-(2^b-1)Lambda>2M(E/s+1/2). For constant d, suitable q,p,Lambda are polynomial; Build/Open are classical PPT. Distinct ORIGINAL witnesses need not share any local state. The toy code's 256-bit root and parameters are not QPT-calibrated.

## Exact FALSE-source theorem: no oracle

Define a certified FALSE subclass F_d by the publicly decidable modular condition e_empty is in Image(A_x). A sufficient certificate is an integer Boolean-ideal degree<=d identity 1=sum_{C,T} t_CT X_T f_C. It yields A_x t=e_empty (mod q) and implies ORIGINAL-FALSE. For EVERY fixed error e and symbol mu, A_x z+e+Delta mu e_empty=A_x(z+Delta mu t)+e mod q. Since uniform z is invariant under translation, the ENTIRE rounded ciphertext distribution, including every target word with independent z/e, is perfectly independent of the hidden K. Explicit SOURCE simulator: sample fresh uniform z' and honest bounded e and emit Round(A_x z'+e), WITHOUT K, witness, SourceOpen, representation, or an ordinary LWE challenge with structured A_x. Exact distribution equality remains equality under arbitrary coherent QPT postprocessing.

Actual certificates instantiated: (a OR b) AND !a AND !b has degree-2 identity 1=(1-a)(1-b)+a+b-ab; (a OR b OR c) AND !a AND !b AND !c has degree-3 identity 1=(1-a)(1-b)(1-c)+a+b+c-ab-ac-bc+abc. The products are clause multipliers. At degree 1 the first FALSE source has a public normalized signed kernel; not all FALSE statements belong to F_d.

## Full public CK/Aux/related-capsule QPT reduction

Use an INDEPENDENT uniformly random LWE generator matrix A_com, never the structured A_x. Exact R71 ordinary QPT decisional LWE foundation: n_L, b_L=ceil(log2(n_L)), q_L=2^(4b_L), m_L=4n_L, z uniform Z_qL^nL, independent signed b_L-bit errors, uniform seed ell=8n_L*b_L bits encoding z and e, generator G_Acom(seed)=encode(A_com z+e) of length 2ell. Straight-line standard PRG expansions yield L>=native-signature length+kappa and L-ell>=lambda at <=T epsilon_LWE QPT distinguishing loss for T generator sample hybrids, conditional on ordinary decisional-QPT-LWE for this EXACT distribution, and quantum advice independent of the seed and hidden z/e. This assumption is independent of witness release and has no verified 128-bit parameter calibration.

The honest independent native signer precommits exact challenge signature sigma and public vpk before funding; scope binds ORIGINAL relation identity, claim/outpoint, branch, anchors/window/context and intended vpk. Set U=G_extended,Acom(K). Publish Dsig=sigma XOR U[0:|sigma|], CK=Hash(domain,scope,vpk,Dsig,U[|sigma|:|sigma|+kappa]), and Aux=deterministic(scope,source,CK,related-capsule references). Do not publish raw K, Hash(K), overlapping PRG bits, target-K-dependent advice or an openable sibling sharing target K. QPT collision/binding and native QPT-EUF-CMA are separate assumptions; no deployed Bitcoin PQ signature or no-EC-keypath functionality is asserted.

For target FALSE x in F_d, sample target source without K by the exact translator and use ONE full-output ordinary-LWE-derived PRG challenge U* for Dsig, CK, Aux, permitted independent related capsules, and adaptive malicious classical/quantum postprocessing TOGETHER. U*=G(K) gives the real joint view; U* uniform perfectly masks sigma even conditional on public CK/Aux. If an adversary returns exact root K', the PRG reduction checks G(K')=U*. In the uniform world ANY returned seed succeeds with probability <=2^(ell-L), by counting the image size. Thus exact FALSE final-root recovery <=Adv_QPT-PRG+2^(ell-L); accepted native signature forgery further reduces to independent QPT native EUF-CMA plus source/checking-key binding if no signature was already provided on that exact path. No SourceOpen oracle, adversary-volunteered representation or quantum rewinding is invoked.

For multiple capsules, independently openable claims/scopes need independent K and z/e, disjoint native signing messages and domain-separated public context. Quantum coherent joint attacks on all classical public outputs are allowed, and independent related openings are simulated jointly. A sibling opening exposing target K or signer coins trivially defeats the theorem and is excluded. Malicious setup choosing A_com, abort-conditioned sampling, corrupt builder retention of honest signer secret, N-of-N graph bypass or keyless Build are NOT proved safe.

## Exact unproved boundary and next work

This FALSE theorem is for rank-refutable x only; degree n yields 2^n monomial rows and is not PPT. If polynomial A_x had e_empty in its image for EVERY FALSE x but all TRUE x had normalized witness kernels, rank testing would decide SAT in polynomial time; the rank-translation route alone cannot be generic without a complexity breakthrough. For hard TRUE instances the structured A_x is not an ordinary uniform-LWE matrix, and arbitrary recovered final key/native forgery still has no extraction to an ORIGINAL witness. R58 public trace and R63/R67 short signed-kernel leaks remain relevant. Required missing equation: Pr[arbitrary QPT attacker recovers the final native capability or forges an accepted signature] <= Pr[R_ORIGINAL(x,Ext^A(full public view))=1]+Adv_independently_justified_QPT+negl(lambda), on hard TRUE x, no supplied representation. Original witness checker stays off Bitcoin; hypothetical native PQ/P2MR and one-honest N-of-N graph/abort/DA are separate obligations.

## Executed provenance

The following V8 JavaScript is the EXACT function executed when this note was published; the JSON output is captured below. It checks two refutation identities, 128 complete false-source/CK/Aux/related/adaptive couplings, exhaustive q=3 histograms for 243 seeds per message, and three distinct genuine ORIGINAL TRUE openings of the same precommitted root. Toy hash/randomness are not cryptography. A separate local Python3/SymPy checker, available in the user's downloadable R74 archive, passed 594 assertions with general compiler and 192 couplings; it is not claimed byte-identical to this JS check.

## Exact executed V8 checker

```javascript
const verifyR74 = function verifyR74(){
 let checked=0,rng=0x741104>>>0;
 const assert=(v,label)=>{checked++;if(!v)throw Error(label+" @"+checked)};
 const next=()=>{rng^=rng<<13;rng^=rng>>>17;rng^=rng<<5;return rng>>>0};
 const rem=(x,q)=>(x%q+q)%q;
 const A2=[[1,0,0,0,0],[-1,1,0,0,0],[-1,0,1,0,0],[1,0,0,1,1]],t2=[1,1,1,-1,0];
 const A3=[[1,0,0,0,0,0,0,0],[-1,1,0,0,0,0,0,0],[-1,0,1,0,0,0,0,0],[-1,0,0,1,0,0,0,0],[1,0,0,0,1,0,0,0],[1,0,0,0,0,1,0,0],[1,0,0,0,0,0,1,0],[-1,0,0,0,0,0,0,1]],t3=[1,1,1,1,-1,-1,-1,1];
 for(const [A,t] of [[A2,t2],[A3,t3]])for(let i=0;i<A.length;i++)assert(A[i].reduce((s,x,j)=>s+x*t[j],0)===(i===0?1:0),"integer refutation");
 const weak=[[0,0],[1,0],[0,1]],rw=[1,0,0];
 for(let j=0;j<2;j++)assert(weak.reduce((s,row,i)=>s+rw[i]*row[j],0)===0,"degree 1 false signed kernel");
 const round=v=>Math.floor(rem(v,65536)/16+.5)%4096;
 const source=(A,z,e,word)=>A.map((row,i)=>round(row.reduce((s,x,j)=>s+x*z[j],0)+e[i]+(i===0?256*word:0)));
 const hash=x=>{let h=2166136261>>>0;for(const c of JSON.stringify(x))h=Math.imul(h^c.charCodeAt(0),16777619)>>>0;return h.toString(16)};
 let couplings=0;
 for(const [A,t,name] of [[A2,t2,"false-2"],[A3,t3,"false-3"]])for(let j=0;j<64;j++){
  const z=Array.from({length:A[0].length},()=>next()%65536),e=Array.from({length:A.length},()=>next()%3-1),word=next()%16;
  const shifted=z.map((v,k)=>rem(v+256*word*t[k],65536));
  const C=source(A,z,e,word),S=source(A,shifted,e,0);
  assert(JSON.stringify(C)===JSON.stringify(S),"exact source translation");
  const U=Array.from({length:96},()=>next()%256),sig=Array.from({length:64},()=>next()%256);
  const ctx=[name,"ORIGINAL-NP","claim:UTXO:0","challenge","anchors:fixed","intended-vk"];
  function fullview(c){
   const Dsig=sig.map((v,i)=>v^U[i]);
   const CK=hash([ctx,Dsig,U.slice(64)]);
   const Aux=hash(["aux",ctx,CK,c]);
   const related=hash(["independent-root-sibling",ctx,Aux]);
   return [c,Dsig,CK,Aux,related,hash(["malicious-adaptive-postprocess",ctx,CK,Aux,related])];
  }
  assert(JSON.stringify(fullview(C))===JSON.stringify(fullview(S)),"complete CK Aux related");
  couplings++;
 }
 const hist=[];
 for(let w=0;w<3;w++){
  let H=new Map();for(let k=0;k<243;k++){
   let tmp=k,z=[];for(let j=0;j<5;j++){z.push(tmp%3);tmp=Math.floor(tmp/3)}
   const c=A2.map((row,i)=>rem(row.reduce((s,x,j)=>s+x*z[j],0)+(i===0?w:0)+i,3));
   const key=JSON.stringify(c);H.set(key,(H.get(key)||0)+1);
  }hist.push(H);
 }
 for(let k=1;k<3;k++){
  assert(hist[0].size===hist[k].size,"hist size");
  for(const [key,count] of hist[0])assert(hist[k].get(key)===count,"full exact histogram");
 }
 const trueA=[[1],[-1],[-1],[1]],R=[[1,1,0,0],[1,0,1,0],[1,1,1,1]];
 const words=Array.from({length:64},()=>next()%16);
 const ct=words.map(w=>source(trueA,[next()%65536],Array.from({length:4},()=>next()%3-1),w));
 for(const r of R){
  assert(r.reduce((s,x,i)=>s+x*trueA[i][0],0)===0,"genuine ORIGINAL witness");
  const got=ct.map(c=>{
   const y=rem(c.reduce((s,x,i)=>s+x*r[i],0),4096);
   const d=Array.from({length:16},(_,u)=>Math.min(rem(y-16*u,4096),rem(16*u-y,4096)));
   const v=d.indexOf(Math.min(...d));assert(d[v]<8,"bound");return v;
  });
  assert(JSON.stringify(got)===JSON.stringify(words),"same precommitted root");
 }
 return {run:"R74-MOMENT-REFUTATION-TRANSLATION-20261104",status:"RESTRICTED_FALSE_FULLVIEW_COMPONENT__NO_GENERIC_WKEM",assertions:checked,false_complete_view_couplings:couplings,exhaustive_q3_generators_per_symbol:243,exhaustive_symbols:3,true_original_witnesses:3,limitations:"Toy: no QPT hardness, no hard-TRUE key-to-ORIGINAL witness reduction or native PQ endpoint"};
};
console.log(JSON.stringify(verifyR74(),null,2));

```

## Captured output

```json
{
  "run": "R74-MOMENT-REFUTATION-TRANSLATION-20261104",
  "status": "RESTRICTED_FALSE_FULLVIEW_COMPONENT__NO_GENERIC_WKEM",
  "assertions": 632,
  "false_complete_view_couplings": 128,
  "exhaustive_q3_generators_per_symbol": 243,
  "exhaustive_symbols": 3,
  "true_original_witnesses": 3,
  "limitations": "Toy: no QPT hardness, no hard-TRUE key-to-ORIGINAL witness reduction or native PQ endpoint"
}
```
