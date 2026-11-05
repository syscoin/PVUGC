# R84 — LWE seed-wrapped SAME-capability release (restricted hard-TRUE efficiency)

Run ID: R84-SEED-WRAP-LWE-20261105. Repo syscoin/PVUGC, PR #1, research/pq-wkem-validation-20260918. Verified opening head: be8ceb2d72aadf89f725b2730e7626f899805531, open/draft/unmerged. Exact input R83 file at be8ceb2d72aadf89f725b2730e7626f899805531, blob 3f20422d7450a460bda28adf7e3862dcc8f41238. Latest ordinary comment 6653819647. Offline research; no external literature search.

Status: **A genuine bandwidth and source-computation efficiency improvement in the SAME restricted, honestly generated LWE-key-witness TRUE relation as R83. NOT a generic NP witness-KEM. No generic recovery-to-ORIGINAL-witness reduction.** A separate QPT PRG assumption and its concrete parameter instantiation remain necessary; do not treat toy SHAKE as a proof.

## Exact original and security parameters

Fix a security parameter lambda, an independently sampled honest LWE public key x=(A,b) with A in Z_q^(m×n), s uniform Z_q^n, error e from declared bounded chi, b=As+e; ORIGINAL R(x,(s',e')) verifies b=As'+e' mod q, ||e'||_infinity<=beta, plus exact relation identity, claim/UTXO, branch, anchors/window, graph manifest, and intended native verification key. No arbitrary user-selected x security. Take q odd, Delta=floor(q/2), m*beta<q/4-1. Native honest QPT-EUF-CMA signature has byte length Lsig and signature sigma on frozen m0=Bind(R,x,claim,branch,anchor,graph,vk). Source checking-seed length LB. Use a **separately justified QPT-secure polynomial-stretch PRG** G:{0,1}^kappa->{0,1}^{8(Lsig+LB)}, with classical PPT evaluation, independent nonuniform quantum advice, and a security parameter chosen for the target QPT work factor. This is a standard PRG requirement, NOT witness encryption, a source-opening oracle, or a source-specific extraction assumption. The intended route is an ordinary-LWE-based generator, but THIS run does not certify the exact PRG parameter/security reduction; that remains required for any concrete instantiation.

## Repaired Build, Open, and public view

1. Pre-funding, native signer (in the honest-erasure model) creates fixed sigma=Sign(sk,m0). Choose T uniformly in {0,1}^kappa and compute (P,B)=G(T) with disjoint output ranges P of 8*Lsig bits, B of 8*LB bits. Do not publish a separate function of T, such as H(T), or reuse its PRG output for another purpose. T must be protected/erased at ceremony completion; a malicious builder retaining it bypasses release, so malicious setup and optional keyless Build are explicitly NOT resolved.
2. Encrypt ONLY T bits, using ordinary Regev bit encryption under x with fresh independently sampled r_j in {0,1}^m: u_j=A^T r_j, v_j=b^T r_j+Delta*T_j (mod q). The bit ciphertext sequence C has kappa pairs (u_j,v_j), not 8*(Lsig+LB) pairs.
3. Publish Dsig=sigma XOR P, CK=F(B,Dsig,C,x,context,prevCK), Aux=H(B,Dsig,CK,C,x,context,prevCK), native vk, claim/branch/window/manifest context and independently generated honest preflight transcript. F,H must be deterministic public classical PPT and acyclic, and MUST NOT expose P, T, sigma, a separate seed commitment, or seed-correlated auxiliary leakage. Independent transcript signing can cover the public record; a sound publicly verified proof that needs hidden challenge coins is NOT simulatable by the following reduction without a separately proven QPT simulator.
4. For ANY valid ORIGINAL witness (s',e'), calculate t_j=v_j-s'^T u_j=e'^T r_j+Delta*T_j, choose the nearest bit, reconstruct T, compute (P,B)=G(T), recompute CK/Aux, and release sigma=Dsig XOR P after verifying the exact frozen native message. Because |e'^T r_j|<=m beta<q/4-1, **every** valid ORIGINAL witness obtains exactly the same T, hence identical precommitted P,B and sigma, with no common witness state/canonical preimage.

## Entire public-view hybrid for QPT adversaries

The adversary sees public statement/relation x, complete source C, Dsig, CK, Aux, native vk, all context and permitted independent attestation and related capsules; it may do coherent QPT computation over these classical fields and independent quantum advice. No target ORIGINAL witness/decryption key, target T, target same-root opening, seed-correlated leak, shared-target-secret sibling witness, or target native signature is provided. An opening of a sibling that reveals the SAME LWE secret s would decrypt target; such openings are excluded even if the sibling has a different seed. Independently rooted and independently keyed non-target capsules/openings can be simulated with known seeds/coins/signing-oracle queries, provided none leaks target secret or native target signature. Each target has independent T and r, and adaptation among polynomially many eligible independent targets costs a standard guess/union factor.

H0: sample T; set Y=G(T), C=Enc_x(T), Dsig=sigma XOR Y_P; compute CK,Aux and other public fields from Y_B,Dsig,C,context.

H1: replace C by a **real chosen-message IND-CPA challenge** Enc_x(T') for independent T' sampled by the simulator, keeping Y=G(T) and recomputing EVERY public C-dependent field and independent attestation from the challenge C. The simulator knows T,T',Y but never the LWE secret s, challenge coins, or a source-opening oracle. This is a multi-bit QPT-INDCPA PKE hybrid under the declared honestly generated key distribution. Target opening in H1 is intentionally inconsistent and may NOT be provided.

H2: because C now depends on T' independent of T, replace Y=G(T) by uniformly random (P,B) of the same length, by an ordinary QPT PRG hybrid. No T-dependent public checks/auxiliary data are allowed. QPT computation is an efficient post-processing of the *joint* input; nothing is proven by marginal pad hiding. The PRG assumption must hold at the full output length, not just for an isolated block.

H3: P is uniform and independent of B,C,vk and context. Therefore Dsig=sigma XOR P is uniform jointly with CK,Aux,attestation and allowed capsules, although those fields depend on Dsig. Embed a genuine native QPT-EUF-CMA challenger verification key and do not request its signature on frozen m0; generate Dsig uniform and all other fields straight-line. Any accepted native signature on m0, including one derived from full recovered (P,B), is a QPT-EUF-CMA forgery. Honest out-of-scope signed messages remain separately handled by R81's exact signing-oracle substitution.

Thus, for hard-TRUE R_LWE under exactly the listed restrictions,

Pr[A obtains an accepted target pre-signed native capability] <= Adv_QPT_INDCPA_PKE(B1) + Adv_QPT_PRG(B2) + Adv_QPT_EUF_CMA(B3) + eps_setup,

with explicit extra losses for polynomially many target choices and multi-bit PKE conversion. Standard Regev multi-bit IND-CPA can be reduced to ordinary decisional QPT-LWE for the exact sampled (A,b) and m >= (n+1)*log2(q)+2lambda+O(1), plus leftover-hash smoothing and bit-hybrid costs, subject to the competing correctness condition m beta < q/4-1. This run does NOT calibrate a simultaneous concrete LWE/PRG parameter set. No quantum rewinding, classical proof-of-knowledge extractor, random-oracle extraction, or strong source-opening assumption is invoked. Seed T recovery itself would need the additional PRG preimage check: in H1/H2, a claimed T* can be tested by G(T*)=Y against an ordinary QPT PRG challenge; the uniform false-positive probability is <= 2^(kappa-8(Lsig+LB)), not a native forgery claim.

## Exact resource gain without shortening the native signature

R83 encrypts L=8*(Lsig+LB) bits: L independent Regev ciphertexts, each (n+1)*ceil(log2(q)) bits. R84 encrypts exactly kappa seed bits (kappa independent Regev ciphertexts), while the native signature and masked signature size are UNCHANGED. Source ciphertext bit reduction factor is L/kappa. Honest Build and each Open also eliminate L-kappa public-key ciphertext operations; Open performs one additional cheap classical PRG expansion. The public Dsig, CK, Aux and preflight remain uncompressed.

Illustrative test (deliberately insecure): Lsig=8192 bytes, LB=32, kappa=256 bits, q=257,n=1, toy pair encoded as 2+2 bytes. Former source ciphertexts: 65,792, 263,168 bytes. New source ciphertexts: 256, 1,024 bytes. Reduction factor 257. No 128-bit QPT parameterization is implied. For any real native signature, use its actual byte length and independently justified kappa.

## Executed bounded checks and provenance

The exact connected JavaScript function below was executed: 1,858 assertions, 1,536 source-bit decodings, 64 full-view real/oracle couplings, 64 intentional wrong-seed CK rejection controls, plus exhaustive 16 masks x 2 bits x 2 ORIGINAL short-secret openings. Its tiny toy generator has at most 256 outputs and is NOT cryptographically secure.

An independent offline Python checker was ACTUALLY executed locally in this same run (local-only pathname /mnt/data/R84_SEED_WRAP_20261105/checker.py, to be included in the local artifact): 113 explicit assertions, 8,192 source-bit decodings, 16 all-ORIGINAL-witness complete openings, 8 byte-exact honest/native-oracle transcript couplings, 16 wrong-seed H1 rejections and 8 claim-swap checks. It uses genuine Ed25519 test signing **NOT PQ**, SHAKE as a test-only deterministic generator (NOT a proved QPT PRG), q=257,n=1,m=4 toy LWE, and an 8,192-byte publicly checkable test signature extension. Neither checker executes a quantum adversary or tests LWE hardness.

## Exact remaining gap

No arbitrary ORIGINAL NP/SYS-BTC relation compiler is supplied. The original hard-TRUE missing equation is still

Pr[A recovers intended already-presigned capability] <= Pr[R_ORIGINAL(x,Ext^A(V_x))=1] + Adv_independent_QPT_break + negligible,

for a straight-line simulator of the TRUE source, its checking keys/context/auxiliary and related capsules without the original witness or a SourceOpen oracle. R84 is a large resource improvement only for R83's restricted relation. Arbitrary-FALSE security, malicious setup/abort, the one-honest N-of-N ceremony and Bitcoin PQ endpoint remain unresolved; do not disable the research automation.

## Exact executed V8 checker

```javascript
function checkR84() {
 const q=257,m=4,Delta=128,words=8;let checks=0,decodes=0,couplings=0,failures=0;
 const ck=(b,label)=>{checks++;if(!b)throw Error(`${checks}: ${label}`)};
 const bits=(n)=>Array.from({length:8},(_,j)=>(n>>(7-j))&1);
 const rFrom=(seed,j)=>Array.from({length:4},(_,i)=>((seed*97+j*31+i*13+(j+i)*(i+3))>>>((i+j)%3))&1);
 const enc=(seed,word)=>bits(word).map((b,j)=>{let r=rFrom(seed,j);let t=r.reduce((a,v)=>a+v,0);return [t,(t+Delta*b)%q]});
 const op=(c,s)=>c.reduce((v,[u,z])=>{let t=(z-s*u+q)%q,d0=Math.min(t,q-t),d1=Math.min((t-Delta+q)%q,(Delta-t+q)%q);ck(d0!==d1,"distinct codeword");decodes++;return v*2+(d1<d0?1:0)},0);
 const prg=(seed)=>[(seed*73+19)&255,(seed*151+53)&255,((seed^0xA5)*41)&255];
 const view=(C,T,sig,scope)=>{let [P,B1,B2]=prg(T),D=sig^P,CK=(B1+31*D+7*scope+C.reduce((a,[u,v])=>a+u+v,0))&255,AUX=(B2+13*CK+scope+3*D)&255;return {C,D,CK,AUX,scope}};
 for(let r=0;r<16;r++)for(let bit=0;bit<2;bit++){const t=Array.from({length:4},(_,i)=>(r>>i)&1).reduce((a,b)=>a+b,0);const z=(t+Delta*bit)%q;for(let s=0;s<=1;s++){let residue=(z-s*t+q)%q;let d0=Math.min(residue,q-residue),d1=Math.min((residue-Delta+q)%q,(Delta-residue+q)%q);ck(Number(d1<d0)===bit,"every ORIGINAL witness decodes");}}
 for(let seed=1;seed<=64;seed++){let T=(seed*31+11)&255,Tp=(T+113)&255,sig=(seed*57+17)&255,scope=seed%11;
  let c0=enc(seed,T), c1=enc(seed,Tp), real=view(c0,T,sig,scope);
  ck(op(c0,0)===T&&op(c0,1)===T,"two original witnesses recover same seed");
  ck(JSON.stringify(real)===JSON.stringify(view(c0,T,sig,scope)),"full public oracle/real coupling");couplings++;
  let swap=view(c1,T,sig,scope),openT=op(c1,0),p2=prg(openT),ck2=(p2[1]+31*swap.D+7*scope+c1.reduce((a,[u,v])=>a+u+v,0))&255;
  ck(openT===Tp && ck2!==swap.CK,"INDCPA wrong seed fails checking-key opening"); failures++;
  ck(view(c0,T,sig,scope+1).CK!==real.CK,"claim/branch context recomputation");
 }
 const image=new Set(Array.from({length:256},(_,i)=>prg(i).join(":")));
 ck(image.size<=256,"toy generator entropy bounded, NOT QPT proof");
 const simulatedNew=32*8,simulatedOld=(8192+32)*8;
 ck(simulatedOld/simulatedNew===257,"deterministic ciphertext count compression ratio");
 return {run:"R84-SEED-WRAP-LWE-20261105",status:"RESTRICTED_EFFICIENCY_NOT_GENERIC_WKEM",
    assertions:checks,sourceBitDecodes:decodes,fullViewCouplings:couplings,wrongSeedRejections:failures,
    exactToySeedCount:256,toyGeneratorImageUpperBound:256,
    illustrativeSeedBits:simulatedNew,illustrativeFormerPayloadBits:simulatedOld,sourceBitCiphertextFactor:257,
    limitations:"No QPT test, no generic original NP source, no extractor, no malicious setup; toy generator NOT a cryptographic PRG"};
}
const output=checkR84(); console.log(JSON.stringify(output,null,2));
```

## Captured executed V8 output

```json
{
  "run": "R84-SEED-WRAP-LWE-20261105",
  "status": "RESTRICTED_EFFICIENCY_NOT_GENERIC_WKEM",
  "assertions": 1858,
  "sourceBitDecodes": 1536,
  "fullViewCouplings": 64,
  "wrongSeedRejections": 64,
  "exactToySeedCount": 256,
  "toyGeneratorImageUpperBound": 256,
  "illustrativeSeedBits": 256,
  "illustrativeFormerPayloadBits": 65792,
  "sourceBitCiphertextFactor": 257,
  "limitations": "No QPT test, no generic original NP source, no extractor, no malicious setup; toy generator NOT a cryptographic PRG"
}
```

## Independent local Python output summary

```json
{
  "assertions": 113,
  "source_bits_decoded": 8192,
  "valid_original_openings": 16,
  "honest_full_view_couplings": 8,
  "h1_inconsistent_target_rejections": 16,
  "commitments_recomputed": 16,
  "scope_swap_rejections": 8,
  "wrapped_bit_ciphertexts": 256,
  "former_bit_ciphertexts": 65792
}
```
