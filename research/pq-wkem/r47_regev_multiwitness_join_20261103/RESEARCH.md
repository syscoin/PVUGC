# R47 — Single-Regev/ORIGINAL witness join: bounded failed construction

**No positive security advance.** This note continues the exact R46 quotient source and R39–R44 Regev-source work. It tests one proposed concrete join rather than assuming an ORIGINAL-to-LWE compiler. The result is a specific obstruction, **not** a generic impossibility for witness encryption. The missing hard-TRUE capability-recovery-to-ORIGINAL-witness reduction remains unsolved.

## Verified starting point and provenance

At the beginning of this iteration syscoin/PVUGC PR #1 was open, draft and unmerged, branch `research/pq-wkem-validation-20260918`, SHA `bdf4b7af07b6cebbb49b56aa5fb534bbb2a441f9`. Latest substantive issue comment observed: 6615063612. Exact-version R46 RESEARCH.md blob `7413e303a4b3b0649e0e9a0ca040d5a23b8b0663`, R35 blob `986ff360ea2853308127ace2b99a5476e4645a92`, R36 blob `97d6211be34d905fe5a10952459b425f74c1f911`. No external literature, web search, whole PR diff or historical-run sweep. The complete extra local Python checker, output and detailed derivation remain separate from the inline V8 checker below.

## Candidate A — different ORIGINAL witnesses as decryption secrets of ONE honest Regev public key

Parameter distribution: odd prime q, n x m matrix A uniform in F_q, secret s uniform in F_q^n (independent of A), centered error e in [-B,B]^m, and public b=A^T s+e mod q; require 4B+1<q. The proposed classical PPT compiler Map(x,w,A,b) would supply a Regev secret s_w for **every** valid ORIGINAL witness w, with residual e_w=b-A^T s_w centered in [-B,B]^m. Distinct w may have different internal states. No SourceOpen oracle is available to the reduction.

For any two different accepting secrets s0 != s1, let d=s0-s1 !=0. Subtraction proves

```text
A^T d = e1-e0 (mod q),  with each centered coordinate in [-2B,2B].
```

For fixed nonzero d and uniform A, A^T d is uniform over F_q^m. Define rho=(4B+1)/q. The probability of this event is **exactly rho^m**. If the first s is independently fixed, union bound over every other secret gives (q^n-1)rho^m. Even if BOTH candidate keys are chosen adaptively after seeing A,b, union bound over all ordered distinct pairs gives q^n(q^n-1)rho^m. This is an unconditional statement about the honest matrix distribution, not an LWE, SIS, extraction or QPT assumption. It is valid even for computationally unbounded key selectors. It says that at ordinary parameters a single honest Regev public key almost never accepts two different small-residual decryption secrets. It **does not apply** to different honest keys per R41 OR branch, or nonlinear decoders that do not output a small-residual Regev secret.

Illustrative q=65537,n=64,m=2048,B=1 has log2 bounds -28012.74, -26988.73 and -25964.73 respectively. These numbers concern multi-secret compatibility and say **nothing** about whether the LWE instance has 128-bit security. Exact exhaustive enumeration gave 1/3125 adaptable collisions at q=5,m=5,B=0; q=11,m=4,B=1 gave 2721/14641, against fixed-difference 625/14641, within the union bounds.

A possible repair maps all valid ORIGINAL w to the **same hidden s**, but no such compiler was instantiated; assuming it merely restates the missing common-source opening mechanism. This does **not** require that other potential architectures use a shared intermediate secret or canonical witness.

## Candidate B — noisy R46 polynomial shares of one honest LWE secret, with attempted public cancellation

Let W_x be the public vector space of clause masks vanishing at every genuine ORIGINAL witness, e.g. R35/R46's product-of-failure masks. The builder independently samples masks M_i in W_x, coefficient-noise polynomials eps_i, and standard honest Regev (A,s,e,b=A^T s+e). Publish the polynomial secret shares

```text
D_i(z) = s_i*1 + M_i(z) + eps_i(z),    u=A*r.
```

For a valid original witness z_w, masks vanish but eps_i(z_w) may be nonzero; directly substituting D_i(z_w) into ordinary Regev decryption adds the uncontrolled term eps(z_w)^T u, generally uniform-sized because u is derived from A. The attempted exact repair makes the encryption publicly polynomial-valued:

```text
V(z) = (b^T r + Delta*mu)*1 + SUM_i u_i eps_i(z) + eta(z).
T(z) = V(z) - SUM_i u_i D_i(z)
     = (Delta*mu + e^T r)*1 - SUM_i u_i M_i(z) + eta(z).
```

This *does* give every valid ORIGINAL witness the same precommitted mu whenever e^T r+eta(z_w) is inside the decoding radius, without a common witness assignment. But T is **public**. For every TRUE instance, because valid evaluations annihilate W_x and evaluate 1 to 1, 1 is not in W_x, so public linear algebra can compute h(W_x)=0,h(1)=1. Thus

```text
h(T) = Delta*mu + e^T r + h(eta).
```

When eta=0 or h(eta) is bounded, the bit is decodable without ANY ORIGINAL witness. Adding a large eta in public-dual directions while keeping eta(z_w) small is precisely the unresolved R35/R46 hard-TRUE pseudoevaluation problem; the Regev layer offers no independent proof of that property. The deterministic q=65537 exact test below uses two distinct genuine ORIGINAL witnesses, z0=0 with z1=0 or 1, nonzero eps_i and eta. It proves both correct-witness opening and full public constant-coefficient key recovery in the same example. The instance is intentionally easy; the algebraic identity applies to arbitrary x, while smallness of h(eta) does not.

## Full joint-public-output and security status

The requested view contains (ORIGINAL x and verifier, source D, ciphertext V, A,b,u, native vk, checking key CK, claim/path/context, auxiliary strings and related capsules). The attempt **does not** yield a QPT LWE challenge simulator that constructs correlated D without knowing the challenged s. Marginal security of (A,b,u) cannot cover the correlated polynomial shares, source openings, CK or selective opening of related capsules. The witness-free public h(T) is already a classical PPT break for the stated small-eta fixture, so extra publicly reproducible CK/aux data cannot restore secrecy. If CK/aux reveals a secret directly, security fails even more plainly. No malicious-setup, arbitrary FALSE, multiple-hard-TRUE, target selective-opening or quantum advice theorem is claimed.

**No repair was established.** Both exact equations above are preserved for further work. Next requirement is a **different nonlinear** ORIGINAL source for which every valid ORIGINAL witness recovers the same K, and for any nonuniform QPT A receiving the complete source/CK/vk/context/aux/related view (plus permitted openings),

```text
Pr[A recovers target K or gives accepted native target signature]
 <= Pr[Ext^A outputs ACTUAL ORIGINAL w: R_x(x,w)=1]
    + Adv_QPT(independently instantiated break) + negligible.
```

The extractor must not require A to volunteer a representation or SourceOpen, and a separate arbitrary-FALSE full-view simulator is required. R45's N-of-N graph, pre-funding DA and abort assumptions and the future no-EC-key-path native PQ Bitcoin endpoint remain conditional. Bitcoin must not evaluate the NP relation, VM, PCP/Kilian or BitVM trace disputes.

## Exact executed V8 checker

The following run function was **actually executed** for this note; output follows. An independent local Python 3.13 finite enumeration and polynomial check was executed twice byte-identically, and is available in the local offline archive.

```js
const run = function check(){
  let assertions=0;
  const assert=(b,s)=>{if(!b)throw Error("Assertion failed: "+s);assertions++};
  const enumCase=(q,m,B)=>{
    let fixed=0,any=0,tot=q**m;
    const good=(a,d)=>a.every(v=>{let u=(v*d)%q;return u<=2*B||u>=q-2*B});
    for(let k=0;k<tot;k++){
      let x=k,a=[]; for(let i=0;i<m;i++){a.push(x%q);x=Math.floor(x/q)}
      if(good(a,1)) fixed++;
      if(Array.from({length:q-1},(_,i)=>i+1).some(d=>good(a,d)))any++;
    }
    const expFixed=(4*B+1)**m;
    assert(fixed===expFixed,"fixed difference count");
    assert(any/tot<=(q-1)*(expFixed/tot)+1e-12,"union bound");
    return {q,m,B,total_matrices:tot,fixed_hits:fixed,adaptive_hits:any,union_bound:(q-1)*expFixed/tot}
  };
  const cases=[enumCase(5,5,0),enumCase(11,4,1)];
  assert(cases[0].adaptive_hits===1 && cases[1].adaptive_hits===2721,"exact enumeration");
  const q=65537,DELTA=(q-1)/2;
  const A=[[3,5,7,11],[13,17,19,23],[29,31,37,41]],s=[417,931,278],e=[1,-1,0,1],r=[1,0,1,1];
  const u=A.map(row=>row.reduce((v,a,j)=>v+a*r[j],0)%q);
  const b=r.map((_,j)=>(A.reduce((v,row,i)=>v+row[j]*s[i],e[j]))%q);
  const base=b.reduce((v,x,j)=>v+x*r[j],0)%q;
  const add=(P,Q)=>P.map((x,i)=>(x+Q[i]+q*3)%q);
  const mul=(t,P)=>P.map(x=>((t*x)%q+q)%q);
  const sub=(P,Q)=>add(P,mul(-1,Q));
  const evalP=(P,z0,z1)=>(P[0]+P[1]*z0+P[2]*z1+P[3]*z0*z1)%q;
  const centered=v=>v<=Math.floor(q/2)?v:v-q;
  const decode=v=>Number(Math.abs(centered((v-DELTA+q)%q))<Math.abs(centered(v)));
  const M=[[0,103,0,17],[0,211,0,23],[0,307,0,31]];
  const eps=[[1,-1,1,-1],[-1,1,-1,1],[1,1,-1,-1]];
  const D=s.map((sk,i)=>add(add([sk,0,0,0],M[i]),eps[i]));
  const eta=[1,1,-1,1];
  let bits=[];
  for(let mu of [0,1]){
    let V=add([base+DELTA*mu,0,0,0],eta);
    for(let i=0;i<s.length;i++)V=add(V,mul(u[i],eps[i]));
    let T=V;
    for(let i=0;i<s.length;i++)T=sub(T,mul(u[i],D[i]));
    const ex=add([DELTA*mu+e.reduce((v,a,j)=>v+a*r[j],0),0,0,0],eta);
    let predicted=ex;
    for(let i=0;i<s.length;i++)predicted=sub(predicted,mul(u[i],M[i]));
    assert(T.every((x,i)=>x===predicted[i]),"symbolic public noise cancellation");
    assert(decode(T[0])===mu,"unauthorized coefficient decoder");
    for(let z1 of [0,1])assert(decode(evalP(T,0,z1))===mu,"two valid original witnesses");
    bits.push({bit:mu,public_recovered:decode(T[0]),witness_recovered:[0,1].map(z1=>decode(evalP(T,0,z1)))});
  }
  const rho=5/65537;
  const illustrative={
    q:65537,n:64,m:2048,B:1,
    log2_fixed_difference:2048*Math.log2(rho),
    log2_fixed_s_union:64*Math.log2(65537)+2048*Math.log2(rho),
    log2_adaptive_pair_union:128*Math.log2(65537)+2048*Math.log2(rho)
  };
  return {run:"R47-SINGLE-REGEV-ORIGINAL-JOIN-20261103",status:"no positive security advance",assertions,finite_cases:cases,public_cancellation:bits,illustrative};
};
console.log(JSON.stringify(run(),null,2));
```

## Captured V8 output

```json
{
  "run": "R47-SINGLE-REGEV-ORIGINAL-JOIN-20261103",
  "status": "no positive security advance",
  "assertions": 13,
  "finite_cases": [
    {
      "q": 5,
      "m": 5,
      "B": 0,
      "total_matrices": 3125,
      "fixed_hits": 1,
      "adaptive_hits": 1,
      "union_bound": 0.00128
    },
    {
      "q": 11,
      "m": 4,
      "B": 1,
      "total_matrices": 14641,
      "fixed_hits": 625,
      "adaptive_hits": 2721,
      "union_bound": 0.4268834096031692
    }
  ],
  "public_cancellation": [
    {
      "bit": 0,
      "public_recovered": 0,
      "witness_recovered": [
        0,
        0
      ]
    },
    {
      "bit": 1,
      "public_recovered": 1,
      "witness_recovered": [
        1,
        1
      ]
    }
  ],
  "illustrative": {
    "q": 65537,
    "n": 64,
    "m": 2048,
    "B": 1,
    "log2_fixed_difference": -28012.73634554675,
    "log2_fixed_s_union": -26988.73493667562,
    "log2_adaptive_pair_union": -25964.733527804496
  }
}
```
