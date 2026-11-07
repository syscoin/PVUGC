# R119 — Iterated ordinary-LWE bit expander for restricted native-signature release

**Run:** R119-ITERATED-ORDINARY-LWE-BIT-EXPANDER-20261106.
**Continuity:** syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, observed initial head 8f946dc4988bef1de12b413dfc64b4c67494f30d, open/draft/unmerged. Exact prior R118 RESEARCH.md blob f721f6323367c0992292422d4d0757e72ae6e0d3; R115 joint-public theorem blob 4e36cc4261d65127b37b0b135e9d5efba02cf7be; R117 exact ciphertext-error bound blob e92e8dbd0faf6d46982db3243f51abd236c08e15.

## Result and scope
The surviving **restricted** source-dependent LWE-credential CNF release now encrypts a **single 9,871-bit uniform seed**, rather than R118's two full scalar-LWE pad secret/error pairs (19,422 bits). A fully instantiated deterministic **three-round PRG from ordinary scalar decisional QPT-LWE** expands this seed to a 62,848-bit mask for one frozen 7,856-byte native signature. Under the SAME already-needed scalar decisional QPT-LWE assumption, no extra PRG/iO/WE/WPRF hardness assumption is postulated. The exact classical polynomial-time expansion and joint-public straight-line QPT hybrids are below. Existing LWE source keys, honest-cut CNF policy, bounded-L1 PKE coins, eight-bit phases, native verification key and claim context are unchanged.

Source ciphertext bytes per occurrence are reduced from **R118 82*576=47,232 to R119 45*576=25,920**, a **21,312-byte / 45.12195% ciphertext-only saving**, or 5,455,872 bytes over 256 occurrences. The once-per-capsule masked native signature becomes 7,856 instead of 7,858 bytes. Source public keys B and A are unchanged; THREE rather than TWO generator LWE matrix-vector products per capsule and polynomial-time big-integer rank operations increase generator work. This is not a whole-transcript size or speed claim.

**Restriction:** This remains the genuine restricted LWE-credential relation, not the arbitrary ORIGINAL NP witness relation. It does NOT prove generic FALSE/hard-TRUE witness encryption, malicious N-of-N ceremony safety, QPT parameter calibration or deployed Bitcoin native PQ endpoints. R111/R112 classical near-key and R114 Boolean-quotient extraction remain rejected generic-source constructions.

## The explicit public-parameter scalar-LWE generator
Use q=65521, d=256, m=2000 and public A sampled uniformly from Z_q^(2000x256). Ordinary scalar decisional QPT-LWE challenges are (A,g), either g=A s+e mod q with s uniform Z_q^256 and independent e uniform [-3,3]^2000, or g uniform Z_q^2000. Adversaries may be arbitrary nonuniform QPT with quantum advice. Honest algorithms are classical PPT. Parameters are NOT independently calibrated to 128-bit QPT hardness.

Let M=q^d 7^m, Q=q^m, slack κ=160, k=ceil(log2 M)+κ=9871, l=floor(log2 Q)-κ=31839, h=l-k=21968.

Deterministic G_A(u) for a uniformly distributed k-bit input u:
1. Interpret u as a k-bit integer; t=u mod M, **without rejection**. Write s_rank=t mod q^d, e_rank=floor(t/q^d); unrank s_rank into d little-endian base-q digits and e_rank into m little-endian base-7 digits minus three. This is a public, exact bijection for t in [0,M).
2. Compute the REAL scalar-LWE vector g=A s+e mod q. Rank it as z=sum_i g_i q^i in [0,Q).
3. Return z mod 2^l as a fixed l-bit string. No secret-dependent public auxiliary or oracle is used.

Exact modulo-distribution lemma: If a uniform integer in [0,N) is reduced modulo R, N=aR+r, its total variation distance from uniform [0,R) is r(R-r)/(NR), at most R/(4N). Thus seed modulo mapping has TV_in <= M/(4*2^k) <2^-160, while output rank modulo 2^l for uniform g has TV_out <=2^l/(4Q)<2^-160. Every bound is an **exact-law statistical inequality** not a Gaussian or heuristic.

Replacing the near-uniform (s,e) with exact scalar-LWE source costs TV_in. A genuine scalar decisional QPT-LWE challenge replaces g with uniform. Applying public rank/modulo and replacing its almost-uniform result by exact uniform l bits costs TV_out. Thus any QPT distinguisher of (A,G_A(U_k)) against (A,U_l), together with independent public A-dependent auxiliary data that the reduction can sample, has advantage <= ε_scalar_LWE +2^-159. This requires no independent PRG assumption, random oracle, rewinding or adversary-supplied opening. Independent honest source B matrices can be generated with known S/E conditional on challenge A; malicious B may be adaptively chosen from actual A and honest B and retained quantum advice.

**Three-round expansion:** sample one uniform u0 in {0,1}^k. For i=0,1,2 calculate v_i=G_A(u_i), split into the LOW k bits u_(i+1) and HIGH h bits o_i. Concatenate o0||o1||o2, length 65,904 bits; take the first 62,848 as the fixed native-signature XOR mask. Sequentially replace each full G output by uniform l bits. After preceding replacements the current seed is an independent *hidden uniform k-bit value*, and the reduction needs only the supplied scalar LWE output to compute the following public rounds; it does not know a challenge s/e or a common short preimage. Sharing public A across rounds is allowed because A is in each scalar-LWE challenge. A straight-line QPT hybrid establishes advantage at most **3(ε_scalar_LWE+2^-159)** for one capsule; for s independent capsule seeds sharing A, hybrid them sequentially, at most 3s transitions. For s=16, the statistical component is <2^-153. These are conditional QPT statements about an actual generator, not tests of hardness.

This is an actual deterministic classical-PPT PRG built under the displayed QPT-LWE assumption. Its proof includes A and all efficiently simulatable public postprocessing. It does not establish security if public auxiliary receipts disclose the underlying seed, generator s/e, or the frozen unmasked signature.

## Exact public source release
Keep R118's genuine independent honest capsule-local LWE source keys S in Z_q^(256x64), E uniform [-3,3]^(2000x64), B=A S+E; a malicious source B is chosen after observing A and honest B, before actual encryption coins. The off-chain **restricted** witness checks bounded source representations and one qualified occurrence for each clause of the monotone CNF policy, including actual claim/path scope. Different valid representations and satisfying credential paths need not share state.

Before irreversible funding the graph's intended frozen native signature σ_j on distinct M_j must bind relation identity, real claim/UTXO, branch, anchors/window, context, challenge path, graph, capsule ID and VK. An authenticated N-of-N ceremony and pre-funding validation/erasure remain separate unfinished obligations.

For each capsule choose one uniform u0 independent of sibling capsules. Define Pad=Expand_A(u0), publish ONE bitwise **Dsig=σ XOR Pad** (7,856 bytes). For policy clauses C1...Cc, create c-1 independent uniform k-bit shares and a final XOR share such that ALL c clause shares XOR to u0. For EACH share append **113 zero bits** to produce exactly 39 groups of 32 bytes. Compute six systematic GF256 Reed–Solomon parity groups, RS(45,39), correcting up to three arbitrary corrupted full ciphertext groups per byte lane. Under EACH credential occurrence in a clause encrypt these 45 groups with actual R118 source PKE, independently sampling genuine uniform bounded-L1 r in [-3,3]^2000 with ||r||_1<=2729; u=A^T r and 64 four-bit symbols μ with phases v_j=B_j^T r+4095μ_j mod65521, publishing 256 canonical 16-bit u values plus 64 rounded phase bytes floor(v_j/256) per group (576 bytes).

Open OFF CHAIN checks actual restricted source representations and policy, decrypts any qualifying occurrence per clause, RS-corrects, verifies all 113 zero padding bits, XOR-recovers the **same precommitted u0**, runs deterministic Expand_A and unmasks the exact same frozen native signature for all accepted restricted witnesses. Native VK verifies against M_j. No NP verifier, general proof, VM step or PCP/BitVM trace runs in Bitcoin.

The full public distribution includes relation/statement, A, all independent honest and dependent malicious B, every ciphertext, Dsig, native VK, claim/UTXO/branch/anchors/window, N-of-N graph, J,CK,Aux, context and RELATED capsules plus permitted classical openings and adversary's coherent quantum advice. All J/CK/Aux must be efficiently recomputable from ACTUAL public bytes and independent simulatable coins after every hybrid. No secret-dependent signature/seed digest, inner SNARG as ORIGINAL extraction or SourceOpen oracle is silently permitted.

## Straight-line full-public QPT reduction, restricted corruption model ONLY
Assume an initially unqualified malicious credential set and a guessed target capsule j plus an **honest-only unsatisfied CNF clause cut** C, where protected honest cut keys, actual encryption coins, and target native signature are never revealed. Noncut target and off-target genuine source-key/coin/signature revelations use known sampled coins; their classical queries may be adaptive. No target signing oracle, qualified malicious set, target-cut opening or quantum-superposition opening oracle. Malicious B may depend on all public honest B and retained quantum advice. Multiple independent sibling capsules are handled by sequential hybrids.

1. For each encrypted protected cut group, use a **genuine exact-distribution source LWE-PKE IND-CPA challenge** (real share versus zero) with the actual source B; after all protected cut ciphertexts become zero, all other c-1 clause shares are jointly uniform and independent of u0. Recompute public CK/J/Aux/context and related outputs from actual challenge bytes, NEVER retained originals. Per cut key this costs **45** actual group hybrids (was 82 in R118). This step inherits R115/R118's conditioned exact-source QPT IND-CPA proof and honest-cut restriction, not a marginal-only pad claim.
2. Having hidden all protected shares, replace the TRUE expanded pad from the deterministic seed by uniform through three genuine standard scalar decisional-QPT-LWE challenges **jointly with the same public A, honest/malicious B, public VK, Dsig, CK/J/Aux and related capsules**. Because noncut shares are independent of u0, simulator needs no hidden generator seed or SourceOpen oracle.
3. With a uniform final bit pad, the target Dsig is uniform independently of the never-revealed σ. Embed an independent native QPT-EUF-CMA public verification key, use signing oracle only for DISTINCT off-target M, and turn any fresh accepted target native signature into a native forgery, with no demand that the adversary volunteer a representation.

For a fixed guessed target and cut (up to explicit binding failures), a conservative displayed loss is:
  Pr[unauthorized fresh native signature] <= 45|C|ε_PKE +3ε_scalar_LWE +3*2^-159 +ε_native_QPT_EUF_CMA +ε_binding.
Account for guessing among s capsules and c_j cuts and for the corresponding 3s PRG hybrids in the complete multiple-capsule experiment, without double counting. QPT reductions are straight-line on classical challenges; retained quantum advice and coherent joint computation carry through public postprocessing. This does NOT prove hard-TRUE arbitrary ORIGINAL witness extraction.

## Simultaneous correctness and computational costs
R117's exact uniform bounded-L1 conditional-moment certificate is retained (not rerun): for any fixed bounded source E column, p_symbol<2^-50; 64 correlated symbols per group give p_group<2^-44 by union without lane independence. Independent group coins plus RS(45,39) allow <=3 failures. For at most 16 capsules x16 credential occurrences, full postview adaptive valid restricted-path correctness failure is bounded by
  256*C(45,4)*2^-176 +(q^256-1)*(13/q)^2000 <2^-150 +2^-20502.54,
using R116's global bounded-source-representation uniqueness event. This is a correctness event, not a QPT attack estimate.

The 45*576-byte source ciphertext saves 45.12195% of **ciphertext-only** bytes; same public A and B dominate other unchanged costs. An extra LWE A*s product per capsule and three base-q rank calculations increase builder evaluation work. Native output with an EC-free P2MR-like path and SLH-like signatures is CONDITIONALLY hypothesized, not deployed or modified.

## Executed verification and exact remaining obligation
The Javascript checker below was executed in the GitHub-connected V8 runtime **before object creation** and passed its recorded assertions. It checks exact integer source and output width inequalities, exhaustive small input/output modulo-TV identities, 4563 small exact source unrank/rank roundtrips, RS counts, CNF same-seed paths and complete finite three-related-capsule final uniform-pad/CK/Aux histograms. Offline independent CPython checker.py, only in LOCAL archive, passed 904 assertions and actually computed three generator rounds with real 2000x256 matrices for three fixtures, including reconstructing the same 7,856-byte masked signature. Independent LOCAL RS(45,39) Berlekamp–Welch full 32-lane decoder corrected three corrupted group symbols and passed 20 assertions. These are finite functionality checks, not QPT-hardness evidence. They do NOT establish 128-bit PQ strength or a generic NP source.

**UNSOLVED equation:** Construct a classical-PPT Comp(R_ORIGINAL,x) that jointly generates real statement-dependent LWE source openings and exact full-public challenge simulator, satisfying Open(Comp(R_ORIGINAL,x),w)=SAME native σ for EVERY valid ORIGINAL witness, while arbitrary unauthorized QPT recovery or accepted native forgery yields an ACTUAL ORIGINAL witness or an independently justified QPT break without asking for an internal representation. Generic fixed-FALSE, arbitrary hard-TRUE extraction, non-canonical distinct-witness representation attacks, malicious N-of-N setup/abort, graph/DA/presignature pre-funding composition, SYS/BTC AuxPoW/coinbase-tag/ancestor/interval/height/fork/censorship source assumptions, QPT parameter calibration, and the hypothetical Bitcoin native endpoint all remain open. One honest graph signer must exclude bypass paths and erase/protect key shares, separate from watcher and ChainLock thresholds. No arbitrary censorship liveness is promised; no online committee, new Bitcoin opcode, CAT, general proof verifier, production change, merge or deployment is authorized. The existing research automation must remain enabled.

## Exact executed checker

~~~javascript
(function(){
"use strict";
const q=65521n,d=256,m=2000,kappa=160;let checks=0;
function ck(x,label){checks++;if(!x)throw Error("check "+checks+": "+label);}
function bits(x){return x.toString(2).length;}
const M=q**BigInt(d)*7n**BigInt(m),Q=q**BigInt(m);
const k=bits(M-1n)+kappa,ell=bits(Q)-1-kappa,h=ell-k;
ck(bits(M)===9711,"M bits");ck(bits(Q)===32000,"Q bits");
ck(k===9871&&ell===31839&&h===21968,"PRG widths");
ck(3*h===65904&&2*h<62848&&3*h>=62848,"three rounds");
ck((1n<<BigInt(k))>=M*(1n<<160n),"input statistical ratio");
ck((1n<<BigInt(ell+160))<=Q,"output statistical ratio");
function tvMod(n,mod){let counts=Array(mod).fill(0);
  for(let i=0;i<n;i++)counts[i%mod]++;
  return counts.reduce((a,c)=>a+Math.abs(c/n-1/mod),0)/2;}
for(let mod=2;mod<=16;mod++)for(let b=1;b<=10;b++){
 const n=2**b,r=n%mod,exact=r*(mod-r)/(mod*n);
 ck(Math.abs(tvMod(n,mod)-exact)<1e-12,"exact input TV");
}
for(let n=2;n<=30;n++)for(let b=1;b<=8;b++){
 const L=2**b,r=n%L,exact=r*(L-r)/(n*L);
 ck(Math.abs(tvMod(n,L)-exact)<1e-12,"exact output TV");
}
for(let t=0n;t<13n**2n*3n**3n;t++){
 let sr=t%(13n**2n),er=t/(13n**2n),ss=[],ee=[];
 for(let j=0;j<2;j++){ss.push(sr%13n);sr/=13n;}
 for(let j=0;j<3;j++){ee.push(er%3n);er/=3n;}
 ck(sr===0n&&er===0n,"source unrank");
 let sp=ss[1]*13n+ss[0],ep=ee[2]*9n+ee[1]*3n+ee[0];
 ck(sp+169n*ep===t,"source bijection");
}
const C=(n,r)=>{let z=1n;for(let i=1;i<=r;i++)z=z*BigInt(n-i+1)/BigInt(i);return z;};
const data=Math.ceil(k/256),groups=data+6;
ck(data===39&&groups===45&&data*256-k===113,"RS and padding");
ck(groups*576===25920&&82*576===47232,"ciphertext bytes");
ck((82-groups)*576===21312,"saved bytes");
ck(256n*C(45,4)<(1n<<26n),"failure union");
const seed=0x123456789ABCDEFn&((1n<<BigInt(k))-1n);
const shares=[17n,42n,99n];shares.push(shares.reduce((a,x)=>a^x,seed));
for(let i=0;i<81;i++)ck(shares.reduce((a,x)=>a^x,0n)===seed,"all credential paths");
function hist(sig){
 let h=new Map();
 for(let a=0;a<16;a++)for(let b=0;b<16;b++)for(let c=0;c<16;c++){
 const mask=[sig^a,((sig+3)%16)^b,((sig+9)%16)^c];
 const ck0=mask.map((v,i)=>(v*5+7*i)%17);
 const aux=mask.map((v,i)=>v^((i+2)*3));
 const key=JSON.stringify(["claim-branch-anchor",mask,ck0,aux]);
 h.set(key,(h.get(key)||0)+1);
 }return JSON.stringify([...h].sort((a,b)=>a[0].localeCompare(b[0])));
}
ck(hist(1)===hist(9),"three-related-capsule uniform-pad checking/Aux law");
return {run:"R119-ITERATED-ORDINARY-LWE-BIT-EXPANDER-20261106",
status:"PASS: exact arithmetic and toy full-public laws, not QPT hardness",
assertions:checks,q:Number(q),d,m,kappa,k,ell,emitted_per_round:h,rounds:3,
three_round_output_bits:3*h,native_signature_bits:62848,
statistical_loss_per_round:"<=2^-159 plus decisional QPT scalar-LWE advantage",
source_seed_padding_bits:113,rs:"GF256 RS(45,39)",
ciphertext_bytes_prior:47232,ciphertext_bytes_new:25920,
all_256_occurrence_correctness_failure:"<2^-150+2^-20502.54",
scope:"restricted CNF LWE credentials, not arbitrary ORIGINAL NP"};
})()
~~~

## Captured actual V8 checker output

~~~json
{
  "run": "R119-ITERATED-ORDINARY-LWE-BIT-EXPANDER-20261106",
  "status": "PASS: exact arithmetic and toy full-public laws, not QPT hardness",
  "assertions": 9600,
  "q": 65521,
  "d": 256,
  "m": 2000,
  "kappa": 160,
  "k": 9871,
  "ell": 31839,
  "emitted_per_round": 21968,
  "rounds": 3,
  "three_round_output_bits": 65904,
  "native_signature_bits": 62848,
  "statistical_loss_per_round": "<=2^-159 plus decisional QPT scalar-LWE advantage",
  "source_seed_padding_bits": 113,
  "rs": "GF256 RS(45,39)",
  "ciphertext_bytes_prior": 47232,
  "ciphertext_bytes_new": 25920,
  "all_256_occurrence_correctness_failure": "<2^-150+2^-20502.54",
  "scope": "restricted CNF LWE credentials, not arbitrary ORIGINAL NP"
}
~~~
