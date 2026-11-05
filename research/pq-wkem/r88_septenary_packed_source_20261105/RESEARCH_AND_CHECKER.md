# R88 — Septenary packed LWE source (restricted efficiency; NOT generic PQ WKEM)

Run R88-SEPTENARY-PACKED-SOURCE-20261105. Repository syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918. Verified open/draft/unmerged starting SHA ea9c976ce425ad4141c1412af484530259d9ed75 and latest substantive ordinary comment 6658486649. Exact predecessor R87 RESEARCH.md blob 571692791688b7c01545d099ad58081925c9dc4e, R86 RESEARCH.md blob f35fa9cd68c0b5ef150e09cdc8f9326566d0f559, restricted full-joint R83 blob 3f20422d7450a460bda28adf7e3862dcc8f41238 were read. Research conducted offline; GitHub used only for continuity/publication.

## One substantive construction change

Extend R87's packed Regev source from random r uniform in {-1,0,1}^m to r uniform in {-a,...,a}^m for a=3, retaining the **same illustrative prime q=65521**, R85 independently instantiated even-q LWE PRG, independent vector-LWE columns, native signature and every-valid-ORIGINAL-witness decoder. The higher alphabet entropy reduces the required source matrix rows without changing the underlying QPT decisional-LWE sample type for q,n,chi or the full-public-output composition. This is a material efficiency improvement ONLY for R83's restricted honestly generated LWE-key-witness TRUE relation; it is not arbitrary ORIGINAL NP extraction and makes no 128-bit-QPT or Bitcoin deployment claim.

## Honest classical-PPT distribution, full source and release

Fix odd q, n,m,ell, bounded independently sampled source error chi supported [-beta,beta] and Delta=floor(q/2). Source setup samples uniform A in Z_q^{m x n}, independent uniform S in Z_q^{n x ell} and E from chi^{m x ell}, publishes B=A S+E mod q. The ORIGINAL relation is strictly R_vec((A,B,context),(S',E')) := [B=A S'+E' mod q, |E'_ij|<=beta, and exact BindOriginal(context)]. This special relation must not be identified with arbitrary SYS/BTC fork evidence; honest setup and no retained source witness are important assumptions.

BindOriginal freezes ORIGINAL relation identity, claim/UTXO, branch, anchors/window, intended native verification key/capability, preauthorized graph and scope. Draw an independent, uniform R85 seed T and independent R85 public PRG matrix A_G; generate disjoint signature pad P and checking seed B_check via R85's exactly specified ordinary-QPT-LWE PRG. Under the separate honest-erasure N-of-N baseline, pre-sign the frozen native target message M: sigma=Sign(sk_native,M). For each g=0,...,ceil(k/ell)-1, sample fresh independent uniform r_g in {-3,-2,-1,0,1,2,3}^m, and publish:
  u_g=A^T r_g mod q;
  v_g,j=B_j^T r_g + Delta*T[g ell+j] mod q, for populated bits.
No r is reused between blocks; no B_j column is repeated within a group. The entire public view is (R_original identity and x, C={(u_g,v_g)}, Dsig=sigma XOR P, native vk, CK, Aux, PRG A_G, bound graph/context/claim/branch, independent public preflight attestation and permitted independently rooted related capsules). CK=F(B_check,Dsig,C,A,B,A_G,context,previousCK) and Aux=H(B_check,Dsig,CK,C,A,B,A_G,context,previousCK) are public deterministic acyclic PPT. They may not directly leak T,P,sigma, decryption keys, fingerprints or other target-secret-correlated information. A public wellformedness proof requiring the challenge ciphertext's unknown encryption coins is not instantiated and is not within this restricted simulation.

For **every valid ORIGINAL restricted witness** (S',E'), compute
  v_g,j - (S'_j)^T u_g = (E'_j)^T r_g + Delta*T[g ell+j] (mod q).
Because |(E'_j)^T r_g| <= 3 m beta, the conservative condition 3 m beta < q/4-1 gives deterministic nearest-center recovery of all bits for ALL such witnesses. Regenerate the identical seed T, identical P and B_check, recompute the entire CK/Aux DAG and verify/return the same precommitted native sigma on frozen M off-chain. Different witnesses can have unrelated secret/error and opening states; no common preimage, canonical witness or on-Bitcoin NP verification is imposed.

## Exact algebra and QPT reduction

The general **unit-difference requirement** is gcd(q,t)=1 for each integer 1<=t<=2a, not just odd q. For uniform D=[A|B] in Z_q^{m x d}, d=n+ell, and any different r,r' in [-a,a]^m, one nonzero coefficient of r-r' is a unit modulo q. Holding all other uniform rows of D fixed, that row makes D^T(r-r') exactly uniform: Pr_D[D^T r=D^T r']=q^{-d}. Thus h_D(r)=D^T r is precisely two-universal. A prime q>2a guarantees the condition; for q=9 and a=2 a difference 3 is nonunit, giving collision probability 1/3 instead of 1/9, so do not extrapolate R87's all-odd-q theorem to larger alphabets.

By the exact collision/Cauchy-Schwarz leftover bound,
 TV((D,D^T r),(D,U(Z_q^d))) <= 0.5 sqrt(q^d/(2a+1)^m).
It is statistical for the **whole classical joint view** and stays valid against coherent QPT postprocessing of that transcript, including independent quantum advice, without quantum rewinding or a random-oracle extraction premise. For genuine B=A S+E, sequential hybrids over ell columns use a real one-column ordinary decisional QPT-LWE challenge with exactly source q,n,m,chi and independently synthesize all other columns. Reusing D with independent r_g, a conditional-hybrid sum over h=ceil(k/ell) blocks gives conservative full-message packed source INDCPA advantage <= 2 ell eps_QPT-LWE_source + 2 h eps_LHL, plus concrete malformed/checking losses. No hidden SourceOpen oracle is required. The smaller sample count at identical q,n,chi requires no stronger *assumption*: truncate a longer-source-LWE challenge to produce the shorter one. Neither LWE premise has been quantitatively calibrated.

In the restricted full-public H0/H1 INDCPA hybrid, the reduction knows T and independent T', obtains actual challenge ciphertext Enc_x(T) or Enc_x(T') with unknown decryption secret and coins, and jointly computes Dsig from known T and honestly generated sigma, CK/Aux from known B_check and actual C, independently attestable preflight, bound graph/context and permissible independently rooted related capsules. It does **not** offer target or same-key witness/seed openings. Then the independent R85 QPT-LWE-PRG hybrid makes P and B_check jointly uniform, so Dsig is exactly independent of unknown target sigma even jointly with CK/Aux. An independent QPT-EUF-CMA native verification-key challenger never signs target M; a recovered already-presigned native target signature is a genuine forgery in the final hybrid. The restricted bound remains
 Pr[unauthorized accepted target native signature] <= 2ell eps_LWE_source + 2h eps_LHL + r_G eps_LWE_PRG + Adv_QPT_EUF_native + eps_attestation/graph.
For polynomial capsules, count actual source blocks and target-selection losses; quantum adversaries may process the entire public classical view coherently. Quantum advice correlated with retained honest source secrets, malicious key setup, same-key witness openings, arbitrary corrupted ceremony, and public proofs requiring unknown encryption randomness are excluded. This is a restricted composition theorem, not generic recovery-to-ORIGINAL.

## Checked resource count and exact limitations

For an **illustrative, uncalibrated** prime q=65521, n=256, ell=16, beta=3 and statistical lambda=128, set
 m_a=ceil(((n+ell)log2(q)+2lambda+2)/log2(2a+1)).
R87 a=1 uses m=2909 rows, public (A,B) 1,582,496 bytes. R88 a=3 uses m=1643 rows, public (A,B) 893,792 bytes: save 688,704 bytes (43.5201%) with canonical 16-bit residues. Worst-case |e^T r| <= 3*1643*3=14787 < q/4-1=16379.25. Packed seed ciphertext still requires 187136 Z_q elements = 374272 bytes at R85's uncalibrated k=11008. Native signature length is unchanged. Public source key plus ciphertext falls from 1,956,768 to 1,268,064 bytes. There is no meaningful random-entropy reduction: 1643 log2(7) and 2909 log2(3) are similar. a=4 violates this worst-case decoding condition. q=65521 primality is checked, but source QPT hardness and native Bitcoin PQ support are not established.

Executed bounded offline Python checker passed 10,403 assertions in a separate local extended fixture; its final code and output are downloadable, not represented as GitHub-tested bytes here. The **exact self-contained JavaScript checker below was executed via connected V8**, passed 10,398 assertions including 1,176 exhaustive two-universal pairs, 8,192 toy bit decodes, 256 distinct-valid-ORIGINAL-witness releases, 256 CK/Aux checks and 257 negative controls. Both fixtures deliberately manufacture multiple witnesses using an insecure zero matrix column and fake pads/signatures; neither establishes any quantum security. The initial local Python run failed due to incorrectly packing 257-range residues in one byte; it was corrected to two-byte canonical encoding before the successful run.

## Exact unresolved ORIGINAL obligation

A generic ORIGINAL NP statement x does not supply the independent LWE decryption secret. Merely labeling R88's independent honest LWE key with a SYS/BTC fork relation is NOT an ORIGINAL witness compiler. Needed is a classical-PPT generic Comp(R_original,x) and actual joint source/challenge simulator, then for all QPT A an extraction/reduction
 Pr[A recovers the already-pre-signed capability from the complete V_x] <= Pr[R_original(x,Ext^A(V_x))=1] + Adv_independent_QPT_break + negl,
where Ext does not demand A hand over an internal representation and every valid ORIGINAL witness opens the SAME precommitted capability. This remains UNSOLVED. Arbitrary-FALSE full-public hiding, malicious one-honest N-of-N setup/abort, pre-funding data availability, conditional native Bitcoin PQ graph, and concrete 128-bit QPT parameters remain open. Do not mark the task complete or disable its automation.

## Exact executed self-contained JavaScript checker


```javascript
function checkerR88(){
  let total=0, universal=0, decoded=0, same=0, dag=0, negative=0;
  function ok(v,label){total++;if(!v)throw new Error(label+" assertion "+total);}
  const q=7, r=[];
  for(let i=-3;i<=3;i++)for(let j=-3;j<=3;j++)r.push([i,j]);
  for(let i=0;i<r.length;i++)for(let j=i+1;j<r.length;j++){
    let count=0;
    for(let d0=0;d0<7;d0++)for(let d1=0;d1<7;d1++)
      if(((d0*(r[i][0]-r[j][0])+d1*(r[i][1]-r[j][1]))%7+7)%7===0)count++;
    ok(count===7,"exact prime field pair collision");universal++;
  }
  const qBad=9;
  let nBad=0;
  for(let d=0;d<9;d++)if((3*d)%qBad===0)nBad++;
  ok(nBad===3,"composite modulus is unsafe for alphabet a=2");negative++;
  const Q=65521, n=256,ell=16, lambda=128,beta=3;
  let prime=true;
  for(let d=2;d*d<=Q;d++)if(Q%d===0)prime=false;
  ok(prime,"prime modulus");
  const N=(n+ell)*Math.log2(Q)+2*lambda+2;
  const mOld=Math.ceil(N/Math.log2(3)),mNew=Math.ceil(N/Math.log2(7));
  ok(mOld===2909&&mNew===1643,"precise row counts");
  ok(3*mNew*beta<Q/4-1,"worst-case all-witness decoding");
  const lhs=Math.log2(.5)+(n+ell)*Math.log2(Q)/2-mNew*Math.log2(7)/2;
  ok(lhs<=-lambda-2,"exact LHL margin on log scale");
  const oldBytes=2*mOld*(n+ell),newBytes=2*mNew*(n+ell);
  ok(oldBytes===1582496&&newBytes===893792,"public key byte counts");
  const qq=257, mm=8, ee=4, delta=128;
  const A=Array.from({length:mm},(_,i)=>[(i*13+7)%qq,0]);
  const E=Array.from({length:mm},(_,i)=>Array.from({length:ee},(_,j)=>(i+j)%3-1));
  const B=A.map((a,i)=>Array.from({length:ee},(_,j)=>(a[0]+E[i][j]+qq)%qq));
  const witnesses=[0,1,2,37].map(z=>Array.from({length:ee},()=>[1,z]));
  const mix=(s,v)=>((Math.imul(s ^ v,1664525)+1013904223)>>>0);
  const center=(x,t)=>Math.min(((x-t)%qq+qq)%qq,((t-x)%qq+qq)%qq);
  for(let c=0;c<64;c++){
    let seed=mix(0x5183,c), T=[];
    for(let b=0;b<32;b++){seed=mix(seed,b);T.push(seed&1);}
    const C=[];
    for(let g=0;g<8;g++){
      const r=Array.from({length:mm},(_,i)=>{seed=mix(seed,(g+1)*101+i);return seed%7-3;});
      const u=Array.from({length:2},(_,k)=>((A.reduce((v,a,i)=>v+a[k]*r[i],0)%qq)+qq)%qq);
      const v=Array.from({length:ee},(_,j)=>((B.reduce((v,a,i)=>v+a[j]*r[i],delta*T[ee*g+j])%qq)+qq)%qq);
      C.push({u,v});
    }
    const P=T.reduce((s,b)=>mix(s,b),c+11);
    const CHECK=T.reduce((s,b)=>mix(s,b),c+127);
    const sig=mix(0x7721,c);
    const dsig=sig^P;
    const ctxt=C.reduce((acc,z)=>z.u.concat(z.v).reduce((s,w)=>mix(s,w),acc),1);
    const CK=mix(mix(CHECK,dsig),ctxt);
    const AUX=mix(mix(CK,CHECK),dsig);
    for(const W of witnesses){
      const bits=[];
      for(let g=0;g<8;g++)for(let j=0;j<ee;j++){
        const u=C[g].u,v=C[g].v[j];
        const x=((v-W[j][0]*u[0]-W[j][1]*u[1])%qq+qq)%qq;
        const bit=+(center(x,delta)<center(x,0));
        ok(bit===T[g*ee+j],"all ORIGINAL witnesses decode bit");
        bits.push(bit);decoded++;
      }
      ok(bits.every((z,i)=>z===T[i]),"same bound seed");same++;
      const p=bits.reduce((s,b)=>mix(s,b),c+11),k=bits.reduce((s,b)=>mix(s,b),c+127);
      ok((dsig^p)===sig,"same precommitted capability");
      ok(mix(mix(k,dsig),ctxt)===CK&&mix(mix(CK,k),dsig)===AUX,"CK/Aux recompute");dag++;
      ok(mix(mix(k,dsig),ctxt^0x55)!==CK,"context binding toy");negative++;
    }
  }
  return {run:"R88-SEPTENARY-PACKED-SOURCE-20261105",assertions:total,universal_pairs:universal,
    source_bit_checks:decoded,same_seed_releases:same,ck_aux_checks:dag,negative_checks:negative,
    key_bytes_old:oldBytes,key_bytes_new:newBytes,rows_old:mOld,rows_new:mNew,
    q:Q,noise_bound:3*mNew*beta,
    status:"RESTRICTED_EFFICIENCY_NOT_GENERIC_OR_QPT_PROOF"};
}
console.log(JSON.stringify(checkerR88(),null,2));
```

## Captured connected V8 output

```json
{
  "run": "R88-SEPTENARY-PACKED-SOURCE-20261105",
  "assertions": 10398,
  "universal_pairs": 1176,
  "source_bit_checks": 8192,
  "same_seed_releases": 256,
  "ck_aux_checks": 256,
  "negative_checks": 257,
  "key_bytes_old": 1582496,
  "key_bytes_new": 893792,
  "rows_old": 2909,
  "rows_new": 1643,
  "q": 65521,
  "noise_bound": 14787,
  "status": "RESTRICTED_EFFICIENCY_NOT_GENERIC_OR_QPT_PROOF"
}
```
