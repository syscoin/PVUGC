# R73 — Global cross-moment probe: exact fixture repair, generic SOURCE still unresolved

**Run** R73-TRUTH-TABLE-MOMENT-PROBE-20261104, 2026-11-04. **Status: NO POSITIVE WKEM SECURITY ADVANCE.** Offline mathematical work. Based on PR #1 branch head `c26296b7c93911d85e52043418c2c3bc8f61ae33`, exact R63 RESEARCH blob `25b55c74f1e72e94cb1a3f7e4f2f00e966696bec`, exact R69 RESEARCH blob `01f91fceb0133fe3a2d2f0ecc4fcfb9a97202141`. No external research.

## 1. Single named candidate and new repair attempt

Candidate: **global-moment truth-table SOURCE** for the R63 3CNF-to-short-kernel compiler, using R66's rounded single-root LWE release. The goal was to repair the public signed-kernel bypass by representing each clause's **complete valid local truth table**, not just the earlier weighted slack vector, then imposing a global cross-moment shared across clauses.

The ORIGINAL-FALSE instance is `x=(a OR b) AND (NOT a) AND (NOT b)`. For the OR clause, valid local assignments are 10,01,11; denote their row weights `u10,u01,u11`. Let row vector
`r=(r0,g_a,g_b,u10,u01,u11,v0a,v0b)`, with global first moments `g_a,g_b` and the forced unary-table rows `v0a,v0b`. Public source matrix `A_x` has seven columns, exactly the linear constraints:

```
C0 = u10 + u01 + u11 - r0
C1 = g_a - u10 - u11
C2 = g_b - u01 - u11
C3 = v0a - r0
C4 = v0b - r0
C5 = g_a
C6 = g_b
```

Every accepted binary representation with `r0=1` would yield an ORIGINAL satisfying assignment, but this instance has none: unary constraints force `g_a=g_b=0`; nonnegative binary OR-table weights then all vanish, contradicting `C0=0`.

**Full-public bypass remains:** `h=(1,0,0,1,1,-1,1,1)` is a *publicly computable signed* kernel of every column, `h0=1`, `||h||1=6`. In local truth-table terms, the invalid pattern 00 is the signed affine combination `(10)+(01)-(11)`. This is a stronger diagnosis than simply inserting extra local labels: complete clause-local truth tables and public global first-moment equalities still do not enforce nonnegative local coefficients on arbitrary public decryption calculations. The false-source distinguisher is classical and therefore QPT.

## 2. Exact source, full view and executed negative check

Classical Build selects independent `z_t <- Z_q^7`, independent `e_t <- {-1,0,1}^8`, a 256-bit precommitted root `K`, and publishes for each 4-bit word `mu_t`:

```
q=2^20; p=2^12; s=q/p=256; Lambda=16; Delta=s*Lambda=4096
Ctilde_t[i] = Round_q_to_p((A_x*z_t)[i] + e_t[i] + Delta*mu_t*[i=0])
```

Here `Round_q_to_p(y)=floor((y mod q)/s+1/2) mod p`. Since `h^T A_x=0`, `h^T Ctilde_t = Lambda*mu_t + eta_t mod p`, with `|eta_t| <= ||h||1*(pE/q+1/2)=3.0234375`. Both exact nearest-codeword conditions `Lambda>2|eta|` and `p-15 Lambda>2|eta|` hold. Thus **every possible error draw** permits decoding the root even though ORIGINAL is false; rounding/packing is no repair.

The joint public view includes the authenticated relation, claim/outpoint, challenge branch, frozen anchors, intended native verification-key identity, all source vectors and a precommitted masked signature `Dsig`. Checking-key `CK` and `Aux` are deterministically correlated with `K`, the scope and source capsule; related scopes are separate. The executed checker uses an explicitly **noncryptographic** hash and synthetic 64-byte signature only for correlation checks; the independently executed offline Python checker uses SHA-256/SHAKE, still synthetic native signatures. Having recovered `K`, the attacker reconstructs Dsig's masked native-like signature, CK and Aux from the full output, without submitting h, a witness or an inner proof. An ordinary uniform-A LWE challenger cannot simulate `A_x` (which is deterministic and statement-dependent), and an `A_x`-structured decisional challenge is distinguishable using h. For raw `Y=A_x z+e`, `|h^T Y|<=6`; for uniform Y, `h^T Y` is uniform mod q because `h0=1`. Classical distinguishing advantage is at least `1-13/q` with this distribution. No QPT hardness assumption saves this source.

## 3. Constructive cross-moment correction on this fixture — but not generic security

Add an explicit **global** second moment row `g_ab`, the clause equation `C7=g_ab-u11=0`, and the unary-derived multiplied equation `C8=g_ab=0` (because a=0 implies ab=0). There is an *exact linear refutation*:

```
C0+C1+C2-C5-C6-C7+C8 = -r0.
```

Therefore the augmented matrix has **no signed kernel with r0=1 at all**, over integers or any modulus. This repairs the specific FALSE witnessless source fixture, not arbitrary NP. For the TRUE relation `a OR b` without unary restrictions, add `g_ab=u11`: the three distinct valid ORIGINAL assignments (10),(01),(11) yield three distinct valid binary moment rows, and the rounded source decoder recovers the **same precommitted root** for all three. The repair does not force shared witness states or a canonical witness.

**Unproved and decisive:** a polynomial-size choice of globally shared moments and multiplied constraints that prevents all invalid signed/public decryption relations for arbitrary ORIGINAL FALSE statements; a suitable QPT-standard-LWE simulator for the actual x-dependent full output; and an arbitrary unauthorized TRUE recovery/native-forgery-to-ORIGINAL-witness-or-independent-PQ-break reduction. Introducing all 2^v global moments is not a PPT generic compiler. Even the degree-2 fixture certificate does not establish these requirements. There is no secure successor to R63 here.

## 4. Models, provenance, next exact equation

Honest algorithms are classical PPT for the finite polynomial local lift shown. Attack is classical, hence applies to arbitrary QPT. No quantum rewinding, classical-to-QPT inference, new hardness premise, signer authority, on-chain NP check, or deployment claim is made. Native-PQ signatures, no-EC-key-path output, N-of-N graph, malicious setup/abort, independently scoped auxiliary and multi-capsule opening policies remain separate requirements. The full-public source is deliberately **FALSE-insecure**, so even joint-CK simulation cannot rescue it.

The included JS function is the exact function executed in the connected V8 runtime; its saved wrapper runs with Node. In this run it checked binary-kernel absence, the signed public kernel and all-witness moment kernel, the global moment linear refutation, 32 complete FALSE root/signature/CK/Aux recoveries (2048 nibbles), and three genuine TRUE moment-witness openings under one source. The independent offline Python checker executed 4701 assertions, 64 complete FALSE recoveries (4096 nibbles), and three TRUE moment openings. Local Python file/output are **not** represented as byte-identical to this JS checker or stored in this PR file. Parameters are deliberately insecure toy sizes; the checks are not quantum security evidence.

**Handoff:** construct `Build_x,Capsule_x,Open_x` and an *actual* independently justified QPT challenge simulation for the statement-dependent source and all CK/Aux/related public fields, with `Open_x(w)=K` for every valid ORIGINAL w, and without assuming a representation volunteered by a key-recovering adversary. Then establish:
`Pr[unauthorized key recovery or accepted native forgery] <= Pr[Ext^A yields ORIGINAL witness] + Adv_independent_QPT + negl(lambda)`.
Neither this exact false-instance moment refutation nor a supplied bounded-representation lemma instantiates that equation.

## 5. Exact executed connected V8 checker

```javascript
function checker(){
 let checks=0,state=0x73001104>>>0; const ck=(b,msg)=>{checks++;if(!b)throw Error("assert "+checks+": "+msg)};
 const R=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;};
 const q=1048576,p=4096,sc=256,lam=16,delta=sc*lam;
 const cols=[[-1,0,0,1,1,1,0,0],[0,1,0,-1,0,-1,0,0],[0,0,1,0,-1,-1,0,0],[-1,0,0,0,0,0,1,0],[-1,0,0,0,0,0,0,1],[0,1,0,0,0,0,0,0],[0,0,1,0,0,0,0,0]];
 const h=[1,0,0,1,1,-1,1,1];
 for(const col of cols)ck(col.reduce((a,v,i)=>a+v*h[i],0)===0,"signed kernel");
 let nBinary=0;
 for(let mask=0;mask<128;mask++){
  const r=[1,...Array.from({length:7},(_,i)=>(mask>>i)&1)];
  if(cols.every(col=>col.reduce((a,v,i)=>a+v*r[i],0)%q===0))nBinary++;
 }
 ck(nBinary===0,"original FALSE has no binary kernel");
 const ext=[...cols.map(c=>[...c,0]),[0,0,0,0,0,-1,0,0,1],[0,0,0,0,0,0,0,0,1]];
 const cert=[1,1,1,0,0,-1,-1,-1,1];
 for(let i=0;i<9;i++)ck(ext.reduce((a,col,j)=>a+col[i]*cert[j],0)===(i===0?-1:0),"global moment identity");
 const A=Array.from({length:8},(_,i)=>cols.map(c=>c[i]));
 const rr=(v,m)=>((v%m)+m)%m;
 const round=y=>Math.floor(rr(y,q)/sc+0.5)%p;
 const encrypt=(M,w)=>{
  const z=Array.from({length:M[0].length},()=>R()%q);
  return M.map((row,i)=>round(row.reduce((a,v,j)=>a+v*z[j],0)+(R()%3)-1+(i===0?delta*w:0)));
 };
 const decode=(C,r)=>{
  const y=rr(C.reduce((a,v,i)=>a+v*r[i],0),p);
  const errors=Array.from({length:16},(_,k)=>Math.min(rr(y-lam*k,p),rr(lam*k-y,p)));
  const best=errors.indexOf(Math.min(...errors));
  ck(errors[best]<lam/2,"decoder spacing");return best;
 };
 const fnv=x=>{let a=2166136261;for(const b of Array.from(x))a=Math.imul(a^b,16777619)>>>0;return a>>>0;};
 const encode=x=>Array.from(JSON.stringify(x)).map(c=>c.charCodeAt(0));
 const stream=(K,len)=>Array.from({length:len},(_,i)=>((K[i%K.length]*29+K[(i+7)%K.length]*17+i*13)&255));
 let stolen=0;
 for(let trial=0;trial<32;trial++){
  const K=Array.from({length:32},()=>R()&255), words=K.flatMap(b=>[b>>4,b&15]);
  const C=words.map(w=>encrypt(A,w));
  const wr=C.map(c=>decode(c,h));
  const Kr=Array.from({length:32},(_,i)=>(wr[2*i]<<4)|wr[2*i+1]);
  ck(Kr.every((v,i)=>v===K[i]),"full root extracted on FALSE");
  const base={relation:"(a OR b) AND (!a) AND (!b)",claim:"outpoint:0",branch:"challenge",anchors:"locked",key:"native-vk",capsule:fnv(encode(C))};
  const S=Array.from({length:64},()=>R()&255),ms=stream(K,64);
  const Dsig=S.map((s,i)=>s^ms[i]), signature=Dsig.map((d,i)=>d^stream(Kr,64)[i]);
  const CK=fnv(encode(["CK",base,K])),Aux=fnv(encode(["AUX",base,CK,K]));
  ck(signature.every((v,i)=>v===S[i]),"native-like signature unmask");
  ck(fnv(encode(["CK",base,Kr]))===CK&&fnv(encode(["AUX",base,CK,Kr]))===Aux,"full CK/Aux correlation");
  stolen++;
 }
 const tcols=[[-1,0,0,1,1,1,0],[0,1,0,-1,0,-1,0],[0,0,1,0,-1,-1,0],[0,0,0,0,0,-1,1]];
 const TM=Array.from({length:7},(_,i)=>tcols.map(c=>c[i]));
 const valid=[[1,1,0,1,0,0,0],[1,0,1,0,1,0,0],[1,1,1,0,0,1,1]];
 const ws=Array.from({length:64},()=>R()%16),Cv=ws.map(w=>encrypt(TM,w));
 for(const r of valid){
   for(const c of tcols)ck(c.reduce((a,v,i)=>a+v*r[i],0)===0,"true kernel");
   ck(Cv.map(c=>decode(c,r)).every((v,i)=>v===ws[i]),"same root all TRUE witnesses");
 }
 ck(lam>2*6*(1/sc+0.5),"signed-noise bound");
 ck(p-15*lam>2*6*(1/sc+0.5),"high nibble spacing");
 return {run:"R73-TRUTH-TABLE-MOMENT-PROBE-20261104",status:"NO_POSITIVE_WKEM_SECURITY_ADVANCE",assertions:checks,false_instance_binary_kernel_count:nBinary,structured_source_false_recoveries:stolen,source_nibbles_extracted:32*64,true_moment_witnesses:3,moment_certificate:"C0+C1+C2-C5-C6-C7+C8=-r0",signed_kernel:h,parameters:{q,p,spacing:lam,noise_bound:6*(1/sc+0.5)},cautions:"Toy source and synthetic checking hashes; no generic NP, QPT hardness or native PQ security"};
}
console.log(JSON.stringify(checker(),null,2));
```

## 6. Captured connected checker output

```json
{
  "run": "R73-TRUTH-TABLE-MOMENT-PROBE-20261104",
  "status": "NO_POSITIVE_WKEM_SECURITY_ADVANCE",
  "assertions": 2370,
  "false_instance_binary_kernel_count": 0,
  "structured_source_false_recoveries": 32,
  "source_nibbles_extracted": 2048,
  "true_moment_witnesses": 3,
  "moment_certificate": "C0+C1+C2-C5-C6-C7+C8=-r0",
  "signed_kernel": [
    1,
    0,
    0,
    1,
    1,
    -1,
    1,
    1
  ],
  "parameters": {
    "q": 1048576,
    "p": 4096,
    "spacing": 16,
    "noise_bound": 3.0234375
  },
  "cautions": "Toy source and synthetic checking hashes; no generic NP, QPT hardness or native PQ security"
}
```
