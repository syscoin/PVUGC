# R57 — WIDE-OTP-ORIGINAL-JOINT (2026-11-04)

**Status: genuine restricted size/composition advance; NO generic PQ witness-KEM and NO hard-TRUE ORIGINAL extraction proof.** This single bounded offline iteration continues R48's full-signature one-time pad and R54–R56's genuine ORIGINAL witness quotient source, while retaining R56 as the primary separate LWE research path. A wider prime-field source encrypts entire 256-bit random-pad blocks, rather than 1-bit or 8-bit chunks. This makes the older statistical-pad route small enough to be a meaningful comparator to the ordinary-QPT-LWE pad; it does **not** turn public linear source masking into hard-TRUE witness encryption.

## Version and source provenance

Before work, syscoin/PVUGC PR #1 was open, draft and unmerged on branch `research/pq-wkem-validation-20260918`, starting head `7971521a7393b4fec370a060c41cc070ba8f4cbe`. Latest substantive ordinary comment R56 was `6624574860`. Exact-version R56 note/checker blobs: `d42fc50506e4679631f1befa5f11b9f6e4806099`/`b98dba1cdae7951bc267a852c6646c40adb83a81`; R54 note/checker: `b93bbeb71ee065b9e5db28c816701339d0690d34`/`d73a52156b81e8e066fcfab0953c177c481b723f`. No external literature or unrelated site.

## Exact arithmetic, classical Build and ORIGINAL-witness release

Work in the Boolean quotient `B_n=F_q[z_0,...,z_{n-1}]/(z_i^2-z_i)` with `q=2^272-237` (hex `0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff13`), `Delta=2^16`, and `0<=mu<2^256`. The field modulus was proved prime by a **55-node recursive Lucas/Pratt certificate** independently checked by an executed stdlib-only Python checker (the complete proof certificate and exact checker are in the downloadable offline R57 archive; local SHA-256 manifest recorded separately). Each 272-bit coefficient is 34 bytes. The cyclic distance between plaintext codewords is

`dmin=min(Delta,q-(2^256-1)Delta)=min(65536,65299)=65299`.

For each preauthorized genuine ORIGINAL branch j, use the actual clause-failure polynomials `f_i` and canonical source module `W_j=span{f_i f_k, i<=k}+span{z_S f_i, |S|<=2}`, public quotient projection `P_j` (kernel W_j) and public canonical section `S_j`. The explicit Boolean coefficient dimension `M_j=2^n` is **exponential for general NP**: no claim of practical generic-NP compilation follows. Honest classical-PPT Build under the **separately conditional** N-of-N one-honest preauthorization, presignature availability, and erasure model obtains a fixed native signature `sigma*=Sign(sk_N,m*(x,M,vk))` on the exact claim/UTXO, ORIGINAL verifier and branch, SYS/BTC anchor/window/tag/ancestor/output predicates, manifest and challenge path **before funding**. The optional keyless Build is not claimed.

Sample a **uniform** `Kpad` of exactly the fixed canonical signature byte length and independent `Kbind<-{0,1}^256`. Publish `D=Encode(sigma*) XOR Kpad`. Partition `Kpad||Kbind` into 32-byte big-endian words (with canonical fixed-size framing if signature length is not divisible by 32). Encrypt each `mu_t` under each authorized branch:

`Z[j,t]=P_j(Delta*mu_t*1 + eta[j,t])`, with each coefficient `eta_i in [-B,B]`.

The public CK and Aux must be freshly versioned and bound to exactly the normalized, canonical, ordered public `(ORIGINAL relation,claim,branch,manifest,vk,m*,D,Z_all,related,context)` and **genuinely depend on hidden Kbind**: `CK=F(Kbind,scope)`, `Aux=AuxAlg(Kbind,CK,scope;independent coins)`. Concrete QPT hash-binding/rebinding security is **additional unproved input**. The executed finite checker does not establish hash or signature hardness.

**OpenWideOTP(j,w)** verifies the real ORIGINAL `R_j(x_j,w)=1` OFF CHAIN; computes `Ev_w(S_j(Z[j,t]))`; decodes the nearest cyclic center among adjacent candidate plaintext words and the endpoints (without enumerating 2^256 words); reconstructs Kpad and Kbind; verifies exact scope/CK/Aux and `Verify_native(vk,m*,sigma*)`; then returns the ordinary bound native signature. Since every source generator vanishes at every valid ORIGINAL witness,

`Ev_w(S_j(Z[j,t]))=Delta*mu_t+Ev_w(eta[j,t]) mod q` and `|Ev_w(eta)|<=M_j B`.

Thus **if `2M_j B<65299`**, every valid ORIGINAL witness of every authorized branch obtains the **identical Build-precommitted sigma***. Witnesses may have completely distinct states. This is correctness, not true-instance secrecy. Bitcoin performs no NP verifier, general proof, VM, PCP/Kilian or SHA trace check; BitVM remains conditional covenant plumbing. No native SLH-like signature/no-EC-key-path P2MR deployment is asserted.

## Full joint certified-FALSE theorem, including secret CK and allowed related capsules

**Game:** predesignated unopened target with a polynomial-size authorized manifest where every included branch has a **publicly checkable, hybrid-invariant** certificate `P_j(1)=0`. All branches may encrypt the same Kpad,Kbind and share correlated coefficient-noise tapes E, provided their whole distribution is samplable in classical PPT independently of the challenge signing secret/pad. The QPT adversary may see all public checking keys, related capsules, auxiliary context and adaptively select preauthorized source records/noise disclosures from a consistent sampled table; unrelated openings need known independently sampled coins/witnesses. The target signing message is fresh, native verification key externally supplied by the EUF challenger, and quantum advice is preparable independently of the challenged sk/sigma/pad conditional on public context. **Exclude** malicious setup, target opening, opened same-pad TRUE sibling, different native-signature messages masked by the same OTP, challenge-dependent auxiliary leakage, dishonest branch addition, and unrestricted or secret-correlated opening oracles.

For every fixed secret word and every correlated E table, pointwise across all j,t:

`P_j(Delta*mu_t*1+eta[j,t])=P_j(eta[j,t])`.

A straight-line simulator samples all E once, independently samples Kbind, generates all Z, then computes the genuinely Kbind-dependent CK/Aux, related records and adaptive disclosures. It does **not** assume a SourceOpen oracle or any internal representation supplied by an adversary. Since the full native-signature-length Kpad is independent and uniform, `D=sigma* XOR Kpad` is uniform even **jointly with that correlated full public view**. Replace D by fresh uniform bytes without signing the target message. A black-box QPT EUF-CMA reduction now outputs any accepted target signature from the adversary as a **fresh-message** native forgery: its signing oracle was never asked to sign the target message. For a fixed authenticated manifest:

`Pr[accepted fresh-target signature] <= Adv_QPT-EUF-CMA_native`.

If adversarial rebinding is enabled, add its *separately justified* QPT authentication advantage. Recovery of the exact OTP from D also reveals sigma and yields the same bound. This is a restricted statistically hidden pad composition, **not** a TRUE/GENERAL-FALSE witness encryption proof, and not a claim that a native Bitcoin PQ signature is currently available. Joint/coherent QPT postprocessing does not change exactly identical classical transcripts with allowed advice. No classical rewinding, random-oracle programming, assumed LWE/source opening oracle or QPT security by toy testing.

## Executed evidence and exact resources

The **full independent local Python verifier**, run twice with byte-identical captured outputs, checked 4,353 assertions, 55 recursive Lucas/Pratt primality certificates, the actual R54 19-clause FALSE and 18-clause TRUE ORIGINAL fixtures under this new field (ranks 64 and 61, witnesses 10,11,43), complete 8KiB placeholder pre-signature/key recovery through **all three ORIGINAL witnesses**, secret-dependent SHA3-256 CK/Aux scope checks and three nontrivial (quotient 2) FALSE ORIGINAL branches with reused noise and 32 full-view couplings. That local verifier/prime certificate/entire derivation is preserved in the offline archive, rather than claimed identical to the separate compact checker embedded below. The **embedded self-contained JavaScript checker was itself actually executed through the connected V8 runtime**; its exact returned output is reproduced below. Neither implementation establishes QPT or 128-bit security. The fixed 8KiB bytes are an *abstract capability test*, not an actual native PQ signature.

For the verified TRUE fixture quotient dimension `c=3`, 8KiB pad = 256 words; each source word occupies `3*34=102` bytes, so pad-source size is **26,112 bytes**. Encrypting the additional independent 32-byte CK seed adds **102 bytes**, total **26,214 source bytes**, excluding the unchanged `D=8KiB`, public CK/context/evidence, graph and one-time amortizable global primality proof. R48's older bitwise+dimension-15 8KiB source was 2,949,120 bytes: 112.94x as large as the new pad-source, although that comparison combines quotient reduction and packing; against R55 at the **same c=3**, its byte-packed pad source would be 98,304 bytes, so wide packing is **3.76x smaller**. Big-integer quotient operations are costlier; no end-to-end practical speed or PQ parameter claim is made.

## Material unresolved reduction and handoff

For hard-TRUE genuine ORIGINAL `x`, complete joint public `V=(R,x,Z,CK,Aux,D,vk,ctx,related capsules/openings)`, and arbitrary QPT A, the unproved requirement remains

`Pr[A(V) recovers native capability or forges] <= Pr[Ext^A outputs ACTUAL ORIGINAL w satisfying R_original(x,w)] + Adv_QPT(independent explicit primitive break)+negl(lambda)`.

An extractor cannot assume a volunteered supplied representation or intermediate witness-derived state. The R53 public-short-pseudoevaluation attack on easy TRUE fixtures is **not repaired by the large field, OTP, or packing**; wider source words may worsen numerical leakage. R49–R56 ordinary LWE developments still fail to instantiate a joint challenge simulator and ORIGINAL extractor for hard TRUE. Also open: general FALSE, malicious one-honest N-of-N setup/abort and graph, pre-funding DA, timely challenge inclusion under realistic censorship, keyless Build, concrete 128-bit QPT resources and the conditional Bitcoin native PQ endpoint. Keep the existing research automation enabled.

## Exact separately executed compact checker

```javascript
function runR57() {
  "use strict";
  const q=(1n<<272n)-237n, D=65536n, L=1n<<256n;
  let assertions=0;
  const ok=(x,label)=>{assertions++;if(!x)throw Error(label);};
  const mod=x=>((x%q)+q)%q, zero=N=>Array(N).fill(0n);
  const ring=n=>{
    const N=1<<n, one=()=>{let a=zero(N);a[0]=1n;return a;}, variable=i=>{let a=zero(N);a[1<<i]=1n;return a;};
    const mul=(a,b)=>{let c=zero(N);for(let i=0;i<N;i++)if(a[i])for(let j=0;j<N;j++)if(b[j])c[i|j]=mod(c[i|j]+a[i]*b[j]);return c;};
    const fail=([vars,bits])=>{let x=one();for(let k=0;k<vars.length;k++){let z=variable(vars[k]);if(!bits[k])z=one().map((t,i)=>mod(t-z[i]));x=mul(x,z);}return x;};
    const ev=(x,w)=>mod(x.reduce((s,t,i)=>s+(((i&w)===i)?t:0n),0n));
    const fixture=clauses=>{
      const f=clauses.map(fail), gs=[];
      for(let i=0;i<f.length;i++)for(let j=i;j<f.length;j++)gs.push(mul(f[i],f[j]));
      for(let i=0;i<N;i++)if(i.toString(2).split("1").length-1<=2){let z=zero(N);z[i]=1n;for(let a of f)gs.push(mul(a,z));}
      let piv=new Map();
      for(let g of gs){let t=g.slice();for(let j=0;j<N;j++){if(!t[j])continue;if(!piv.has(j)){let inv=1n,base=t[j],power=q-2n;while(power){if(power&1n)inv=mod(inv*base);base=mod(base*base);power>>=1n;}piv.set(j,t.map(u=>mod(u*inv)));break;}let rr=piv.get(j), co=t[j];t=t.map((u,i)=>mod(u-co*rr[i]));}}
      const indices=[...piv.keys()].sort((a,b)=>a-b), free=Array.from({length:N},(_,i)=>i).filter(i=>!piv.has(i));
      const P=x=>{let t=x.map(mod);for(let j of indices)if(t[j]){let co=t[j],r=piv.get(j);t=t.map((u,i)=>mod(u-co*r[i]));}return free.map(i=>t[i]);};
      const S=z=>{let t=zero(N);free.forEach((i,j)=>t[i]=z[j]);return t;};
      const valid=Array.from({length:N},(_,i)=>i).filter(w=>f.every(a=>ev(a,w)===0n));
      return {N,rank:indices.length,dim:free.length,P,S,valid,ev};
    };
    return {N,one,fixture};
  };
  ok(q-(L-1n)*D===65299n,"cyclic endpoint gap");
  const clauses=[
    [[1,3,4],[0,0,0]],[[0,1,4],[0,0,0]],[[0,1,4],[1,0,1]],[[1,3,5],[1,0,1]],
    [[1,3,4],[1,0,0]],[[0,1,2],[0,0,0]],[[0,3,4],[0,1,1]],[[2,3,5],[1,0,0]],
    [[0,4,5],[1,1,0]],[[1,2,5],[1,1,1]],[[1,2,4],[1,0,0]],[[0,3,4],[1,0,0]],
    [[0,4,5],[0,0,1]],[[2,4,5],[1,0,0]],[[2,3,4],[0,1,1]],[[0,3,5],[0,0,1]],
    [[0,4,5],[0,1,0]],[[1,3,4],[0,1,0]],[[1,2,4],[1,1,0]]
  ];
  const r6=ring(6), bad=r6.fixture(clauses),good=r6.fixture(clauses.filter((_,i)=>i!==10));
  ok(bad.rank===64 && bad.dim===0,"19-clause rank");
  ok(good.rank===61 && good.dim===3,"18-clause rank");
  ok(JSON.stringify(good.valid)==="[10,11,43]" && bad.valid.length===0,"actual originals");
  ok(bad.P(r6.one()).length===0,"certified false");
  const eta=(n,seed)=>Array.from({length:n},(_,i)=>BigInt((seed*19+i*13)%3-1));
  const cap=(f,t,e)=>{let v=e.slice();v[0]+=D*t;return f.P(v);};
  const recover=(f,z,w)=>{
    let c=f.ev(f.S(z),w), h=c/D, options=[0n,L-1n,h,h+1n].filter(v=>v>=0n&&v<L);
    const dist=t=>{let x=mod(c-D*t),y=mod(D*t-c);return x<y?x:y;};
    let win=options.reduce((a,b)=>dist(a)<=dist(b)?a:b);
    ok(dist(win)<=64n,"error decoder");
    return win;
  };
  let openings=0;
  for(let k=0;k<257;k++){
    let t=mod(BigInt(k+17)*0x873f3461c38d7b45265f0b22bc7f1a5b80713afec3d9n)&(L-1n);
    let z=cap(good,t,eta(64,k));
    for(let w of good.valid){ok(recover(good,z,w)===t,"same 256-bit original payload");openings++;}
  }
  const r4=ring(4),ff=[0,1,2].map(k=>r4.fixture([[[k,k,k],[1,1,1]],[[k,k,k],[0,0,0]]]));
  for(let f of ff){ok(f.dim===2,"nonempty false quotient");ok(f.P(r4.one()).every(t=>t===0n),"false public certificate");}
  let couplings=0;
  for(let j=0;j<32;j++){
    for(let k=0;k<10;k++){
      let e=eta(16,k+j*17),a=(BigInt(j)*0x94ab3841n+BigInt(k))&(L-1n),b=(a^0x1729a3f88bn)&(L-1n);
      for(let f of ff){let x=cap(f,a,e),y=cap(f,b,e);ok(JSON.stringify(x.map(String))===JSON.stringify(y.map(String)),"same-noise correlated false source");couplings++;}
    }
  }
  return {run:"R57-WIDE-OTP-ORIGINAL-JOINT-20261104",checks:assertions,prime_field:"2^272-237",prime_certificate:"55-node Pratt verified independently offline",gap:65299,certified_false_rank:bad.rank,true_rank:good.rank,true_witnesses:good.valid,correct_256bit_original_openings:openings,correlated_false_same_secret_couplings:couplings,pad_8192_bytes_source_bytes:26112,pad_and_kbind_source_bytes:26214,hard_true_extraction:"UNPROVED",qpt_hardness_tested:false};
}
console.log(JSON.stringify(runR57(),null,2));

```

## Captured output

```json
{
  "run": "R57-WIDE-OTP-ORIGINAL-JOINT-20261104",
  "checks": 2513,
  "prime_field": "2^272-237",
  "prime_certificate": "55-node Pratt verified independently offline",
  "gap": 65299,
  "certified_false_rank": 64,
  "true_rank": 61,
  "true_witnesses": [
    10,
    11,
    43
  ],
  "correct_256bit_original_openings": 771,
  "correlated_false_same_secret_couplings": 960,
  "pad_8192_bytes_source_bytes": 26112,
  "pad_and_kbind_source_bytes": 26214,
  "hard_true_extraction": "UNPROVED",
  "qpt_hardness_tested": false
}
```

**Local artifact hashes (SHA-256):** full `R57_RESEARCH.md` = separate locally preserved source of the detailed derivation; `R57_CHECKER.py` `7da222e80eb7eb09e96978f455e48bc62a19ab2b33e476bd11ecc21decaf32a6`; `R57_PRIME_CERT.json` `4b6783a76cc96ee889b8157bf5b3581ba0d1d3dce871a90f4e34d3eda0721da4`; exact local `R57_OUTPUT.json` `97f489f41eb3aac2205cb86257669a2ab687dcc352c43b2e319661f372a7d51c`. The offline archive SHA-256 is `e4037933c2ee4af2a6a7b30b45d9a0a2a8ca40c23a0d813e96b7a958ae33f355`. These full local files are not claimed byte-identical to the embedded JS checker.

