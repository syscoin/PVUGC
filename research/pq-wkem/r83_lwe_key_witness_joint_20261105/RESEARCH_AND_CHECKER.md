# R83 — A fully instantiated joint LWE challenge in a restricted hard-TRUE ORIGINAL-witness relation

Run: R83-LWE-KEY-WITNESS-JOINT-20261105. Status: **RESTRICTED positive composition, NOT a generic NP witness-KEM or a proof of the missing generic ORIGINAL extractor**.

## Exact continuity and target

Current syscoin/PVUGC PR #1 verified open/draft/unmerged, branch \`research/pq-wkem-validation-20260918\`, at starting SHA \`c20ffa8afd37b4b02cb0732cc8580b8346995cd1\`; latest substantive top-level comment 6652685898 (R82). Exact R82 blob d0ff1986972ed7ca2102682eb309b8f6e386426a and R81 proof blob 7854382541a0ab5bd6ee4462dc71bc4484775393 read. No external research, PR diff sweep, or archive replay.

Explicit candidate: instantiate **source plus ordinary-LWE challenge simulator together** in a deliberately restricted, genuinely hard-TRUE-on-average ORIGINAL relation, rather than stipulating SourceOpen or a shared-hidden-value release oracle. This is an independently grounded control case for the still-missing **generic** NP compiler.

## Statement, ALL-witness release, and honest classical-PPT Build

For odd modulus q, public A in Zq^(m×n), b in Zq^m, and small bound beta, define

    x=(A,b),   R_LWE(x,(s,e)) = [b = A*s+e (mod q) AND ||e||_infty <= beta],

with centered representatives for e and exact bit-encoding/length checks. The original relation/statement identifier also binds claim/UTXO, branch, anchors/window/context, immutable graph manifest and intended native verification key; x is the specific LWE-short-secret relation, **not** the original SYS/BTC fork-authentication NP relation and not a generic NP compiler.

Honest statement distribution (essential for security, not merely completeness): independently sample A uniformly, secret s uniformly, and noise vector e from a declared efficiently sampled bounded LWE distribution chi supported in [-beta,beta], and publish b=A*s+e. Honest builder receives the public x, **not s or e**. This class consists of hard TRUE samples under the stated decisional-QPT-LWE assumption; arbitrary user-chosen x, maliciously constructed keys, leaking advice or a participant retaining s are outside its security theorem.

Choose Delta=floor(q/2) and require m*beta strictly smaller than the nearest-decision gap (sufficient condition m*beta < q/4 - 1). Generate independent native signing key sk_h and pre-authorize a **frozen** finite message m0=Bind(R_LWE,x,claim,branch,anchor,graph,vk_h), with sigma=Sign(sk_h,m0). Let L=length(sigma)+length(B), choose P in {0,1}^length(sigma) and independent B in {0,1}^length(B), K=P||B uniformly at random.

Encrypt **every bit K_j** under x with freshly independent r_j in {0,1}^m:

    u_j = A^T r_j (mod q),
    v_j = b^T r_j + Delta*K_j (mod q),
    C_j=(u_j,v_j).

Build, knowing K and every r_j, publishes C, Dsig=sigma XOR P, public context and native vk; CK=F(B,Dsig,C,context,prev_CK) and Aux=G(B,Dsig,CK,C,context,prev_CK), with F,G explicitly public deterministic PPT, acyclic, and **no direct P/sigma input**. The optional pre-funding public attestation in the checked fixture is an independent signer signature over the full public record; in the real honest ceremony it is issued only after checking the private consistency data. It is NOT a stand-in for a publicly verified NIZK, N-of-N graph proof, or malicious-ceremony security.

Open(x,w,C,Dsig,CK,Aux): for **any** ORIGINAL witness w=(s',e') meeting R_LWE, compute t_j=v_j-(s')^T u_j=e'^T r_j+Delta*K_j modulo q. Because |e'^T r_j|<=m*beta, rounding to the closer of 0 and Delta yields the same K_j for **every** valid w, even distinct secrets and errors. Reconstruct the one precommitted K, recompute CK/Aux, release sigma=Dsig XOR P and verify native signature on the one frozen message. Different witnesses retain their own distinct s', e' and intermediate values; no canonical witness/common preimage is required.

## Actual ordinary-LWE challenge embedding and full-public QPT game

Assume **standard decisional QPT-LWE for exactly the declared distribution** (A,A*s+e) vs (A,u), for nonuniform QPT distinguishers with independent quantum advice; not an unnamed witness-encryption, source-opening or generic SIS assumption. For ordinary Regev-style PKE, m >= (n+1)*log2(q)+2*lambda+O(1) permits leftover-hash smoothing of (A^T r,b^T r) with uniform public b. With q sufficiently larger than m*beta to preserve decoding, this yields multi-bit IND-CPA from ordinary decisional-QPT-LWE plus statistical loss via a straight-line hybrid over L encrypted bits. The noise and parameter regime must be instantiated and calibrated; **no 128-bit or worst-case-reduction claim is made here**.

Let A_Q be arbitrary QPT with classical public target capsule (x,C,Dsig,CK,Aux,attestation,context) and independent quantum advice. No oracle gives the target ORIGINAL witness, target source decryption or same-root opening; otherwise release is authorized. Non-target capsules/selected openings may be generated independently with known secrets and native signing-oracle queries only for **different** authorized messages. No coherent decryption-oracle queries, secret-key-correlated auxiliary leakage, malicious statement-key generation, challenge-dependent signer advice or shared target-root reveal. Independent native signature scheme is QPT-EUF-CMA on the **exact frozen target message**.

H0 (real): sample K=(P,B), encrypt it as C=Enc_x(K), use genuine sigma and Dsig=sigma XOR P, generate CK/Aux and independent attestation on exactly these public fields.

H1: independently sample K' and use **one real chosen-message IND-CPA challenge** Enc_x(K) versus Enc_x(K') for C, while computing Dsig, CK, Aux, attestation and any permitted related public fields from the known K, sigma, challenge C and context. The simulator does not know the LWE decryption secret s, the challenge encryption randomness r_j, or a SOURCE-opening representation. It can compute all public checking-key and auxiliary correlations because they depend only on C and known K. In the K' branch C deliberately does NOT open the K used by Dsig. This inconsistency is computationally hidden under the stated PKE IND-CPA game, NOT an exact source-coin translation. Independent public attestations sign the public transcript; an obligatory public sound proof requiring the **unknown challenge encryption coins** would invalidate this reduction unless separately given a genuine straight-line QPT simulator.

H2: in the K' branch, P is independent uniform, disjoint from B and C. Thus Dsig=sigma XOR P is exactly uniform, **jointly** with C, CK, Aux, context, attestation and independently generated related capsules, even though those fields may use Dsig. Replace Dsig by independently sampled uniform bytes. The reduction now needs only the native challenge verification key, not sigma or a target signing-oracle query. An accepted signature on the **already preauthorized target message** is therefore a genuine QPT-EUF-CMA forgery in H2. If A outputs K, its P likewise unmasks a valid signature, so full-root recovery is included.

Precisely, for the restricted honest-KeyGen class and allowed full public views,

    Pr_H0[A recovers K or produces accepted target native signature]
        <= Adv_QPT_INDCPA_PKE(B1) + Adv_QPT_EUF-CMA_Sig(B2)

(up to the parameter-dependent multi-bit decisional-QPT-LWE/statistical conversion, probability of malformed preflight or incorrect keygen and whatever explicit graph-bypass risk is excluded). A straight-line reduction embeds the genuine challenge ciphertext and generates **all checking-key/auxiliary/attestation correlations together**, with no quantum rewinding or SourceOpen oracle. The same-root TRUE target must remain unopened. For polynomially many independent target choices add a standard guess/union loss, with no key/coin reuse across independent target capsules.

This is genuinely instantiated for an LWE-short-secret relation: IND-CPA reduces to ordinary decisional LWE (plus statistical smoothing), NOT a new assumption that already grants common-secret release. It is **not** a generic witness-KEM because arbitrary ORIGINAL NP statements have no established classical-PPT compiler to an indistinguishable honestly generated LWE public key whose every ORIGINAL witness maps to a correct decryption secret. In particular, blindly replacing arbitrary x by a native LWE KEM or requiring a witness-holder to generate the statement would silently change the use case and setup threat model.

## Bounded tests and actual limitations

An independent offline Python fixture used 8 complete 768-bit source capsules, Ed25519 test signatures, two DIFFERENT valid LWE-short-error ORIGINAL witnesses s=0,e=(1,1,1,1) and s=1,e=0, real-vs-signing-oracle full public-view couplings, exact INDCPA H0 challenge-ciphertext substitution, H1 intentional source/message inconsistency, checking-key/auxiliary recomputation, separate preflight attestation signatures, and claim-replay rejection. The fixture parameters q=257,n=1,m=4,beta=1,A=(1,1,1,1),b=(1,1,1,1) are **trivially insecure** and expressly NOT an LWE security sample; Ed25519 is NOT PQ. The local Python checker passed 304 explicit assertions while performing 12,288 source-bit recovery operations, with 8 complete public-view oracle couplings and 16 checking-key/preflight opening checks. This independent fuller fixture is local-only and available as a downloadable artifact.

The exact connected V8 checker and its captured output follow, including exhaustive two-witness bit correctness and an exact uniform-pad/CK/Aux histogram; its arithmetic/hashes are likewise INSECURE toys and cannot establish INDCPA or QPT hardness. No arbitrary-FALSE or arbitrary-hard-TRUE generic NP theorem, full honest N-of-N/setup/abort/data availability, 128-bit resource estimate, SOURCE authenticity for SYS/BTC, or deployed Bitcoin native PQ endpoint. This is a restricted compositional benchmark, **not the stopping criterion**.

## Next missing generic equation

Find a classical-PPT compiler Comp(R_original,x) whose **public x-dependent source distribution** is jointly simulatable from a genuine ordinary QPT-LWE challenge without the challenge secret, while all original w satisfying R_original(x,w)=1 recover one same precommitted K and arbitrary QPT same-message capability recovery yields w or an independent QPT break. Crucially the compiler must preserve ORIGINAL authentication, not require malicious witness-holder cooperation, and must supply all checking/auxiliary/related/preflight correlations. This R83 example proves that the hybrid architecture is algebraically coherent for a special NP relation but supplies **no generic transformation** and no ORIGINAL extractor.

No external research or production change. Do not disable the existing automation.

## Exact executed connected V8 checker

```javascript
function checkR83() {
  const q=257, delta=128, m=4;
  let assertions=0, witnessBitChecks=0, histChecks=0;
  function ck(v,label){assertions++;if(!v)throw Error(`${assertions}: ${label}`);}
  function encByte(byte,seed){
    let state=seed>>>0, out=[];
    function next(){state=(Math.imul(state,1664525)+1013904223)>>>0;return state&1;}
    for(let j=0;j<8;j++){
      const bits=Array.from({length:m},next), t=bits.reduce((a,b)=>a+b,0);
      out.push([t,(t+delta*((byte>>(7-j))&1))%q]);
    }
    return out;
  }
  function open(ct,s){
    let b=0;
    for(const [u,v] of ct){
      const t=(v-s*u+q)%q;
      const d0=Math.min(t,q-t),d1=Math.min(Math.abs(t-delta),q-Math.abs(t-delta));
      b=(b<<1)|(d1<d0?1:0);
    }
    return b;
  }
  for(let bit=0;bit<2;bit++)for(let r=0;r<(1<<m);r++){
    const k=Array.from({length:m},(_,i)=>(r>>i)&1).reduce((a,b)=>a+b,0);
    for(const s of [0,1]){
      const t=(k+delta*bit-s*k+q)%q;
      const d0=Math.min(t,q-t),d1=Math.min(Math.abs(t-delta),q-Math.abs(t-delta));
      ck(Number(d1<d0)===bit, "every original short-error witness decodes exact bit");
      witnessBitChecks++;
    }
  }
  for(let seed=1;seed<=24;seed++){
    const k=0xa5, kp=0x5a, sigma=(17*seed+29)%256,b=seed%8;
    const c0=encByte(k,seed),c1=encByte(kp,seed);
    const d=sigma^k;
    const sourceHash=c=>c.reduce((a,x)=>(a+x[0]+3*x[1])%256,0);
    const make=(c,padRoot)=> {
      const D=sigma^padRoot;
      const C=(b+17*D+sourceHash(c))%256;
      const aux=(3*b+C+5*D)%256;
      return JSON.stringify({ciphertext:c,dsig:D,ck:C,aux,context:"claim/branch/nativeVK/frozen-manifest"});
    };
    ck(make(c0,k)===make(encByte(k,seed),k),"H0 chosen-message LWE challenger perfectly reproduces real view");
    ck(open(c0,0)===k&&open(c0,1)===k,"two original witnesses same target capability");
    ck(open(c1,0)===kp&&open(c1,1)===kp,"H1 source encrypts unrelated key");
    ck(make(c1,k)!==make(c0,k),"H1 changes encrypted source and dependent CK/Aux");
    ck(d===(sigma^k),"source/signature hybrid preserved D");
  }
  function histogram(sigma,c){
    const h=new Map();
    const sh=c.reduce((a,x)=>(a+x[0]+3*x[1])%256,0);
    for(let b=0;b<8;b++)for(let P=0;P<256;P++){
      const D=sigma^P,CK=(b+17*D+sh)%256,aux=(3*b+CK+5*D)%256;
      const k=`${D}:${CK}:${aux}`;
      h.set(k,(h.get(k)||0)+1);
    }
    return h;
  }
  const c=encByte(0x5a,12345);
  const h0=histogram(17,c),h1=histogram(203,c);
  ck(h0.size===h1.size&&[...h0].every(([k,v])=>h1.get(k)===v),
    "entire CK/Aux/Dsig joint distribution independent of unknown native signature");
  histChecks+=h0.size;
  ck((17^0)!==(203^0),"negative control raw P together with D exposes native signature");
  return {run:"R83-LWE-KEY-WITNESS-JOINT-20261105",status:"RESTRICTED_SPECIAL_NP_COMPOSITION_NOT_GENERIC_WKEM",
   assertions,witnessBitChecks,histogramSupport:histChecks,
   cases:"all 2^4 encryption masks per bit; 24 coupled source/full-view fixtures; full 8x256 pad enumerations",
   params:{q,delta,m,beta:1,A:[1,1,1,1],b:[1,1,1,1]},
   witnessSecrets:[0,1],result:"Exact all-witness correctness and split-pad coupling in deliberately insecure toy source",
   limits:"No QPT test, no generic ORIGINAL compiler, no source-key hiding proof for user-chosen x, no N-of-N/Bitcoin implementation"};
}
```

## Captured checker output

```json
{
  "run": "R83-LWE-KEY-WITNESS-JOINT-20261105",
  "status": "RESTRICTED_SPECIAL_NP_COMPOSITION_NOT_GENERIC_WKEM",
  "assertions": 186,
  "witnessBitChecks": 64,
  "histogramSupport": 2048,
  "cases": "all 2^4 encryption masks per bit; 24 coupled source/full-view fixtures; full 8x256 pad enumerations",
  "params": {
    "q": 257,
    "delta": 128,
    "m": 4,
    "beta": 1,
    "A": [
      1,
      1,
      1,
      1
    ],
    "b": [
      1,
      1,
      1,
      1
    ]
  },
  "witnessSecrets": [
    0,
    1
  ],
  "result": "Exact all-witness correctness and split-pad coupling in deliberately insecure toy source",
  "limits": "No QPT test, no generic ORIGINAL compiler, no source-key hiding proof for user-chosen x, no N-of-N/Bitcoin implementation"
}
```
