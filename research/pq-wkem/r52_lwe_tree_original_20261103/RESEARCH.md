# R52 — LWE-TREE-ORIGINAL-MATRIX: an explicit LWE expansion replacing R51's separate SHAKE PRG premise

**Scope and provenance.** One bounded offline research iteration, from verified open/draft/unmerged syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918, starting head b2e235ee2a12cfc3f22b5d595f3a24454e64ee5e; last substantive PR comment 6620332582. Exact R51, R49 and R46 research and R51 checker were read at this SHA. No external internet research, complete PR diff, historical sweep, autonomous agent, security/deployment claim, or production edit. The full independently generated extended note and longer checker are retained in the local R52 archive. The exact standalone checker executed twice is included verbatim below with captured output.

## Constructive improvement and scope

R51 hides a 256-bit SHAKE256 expansion seed using ORIGINAL-NP quotient capsules; it achieves good illustrative size but needs an *additional, independently unproved QPT-SHAKE PRG assumption*. Merely publishing a PRG seed defeats ordinary pseudorandomness. R52 replaces the named hash expander with a fully specified binary-tree generator based on a **standard explicit average-case QPT decisional-LWE game**. Its target root is encrypted by the same genuine ORIGINAL-NP quotient source, and the exact prior secret-K_bind-correlated checking key and native pre-signature release mechanism remain. This removes an unrelated PRG hardness premise, but increases encrypted seed length and uses an amortizable public random LWE matrix. This is an *instantiated restricted composition and QPT hybrid*, NOT the missing hard-TRUE witness-KEM proof.

## Exact independent primitive and algorithms

Choose q0=2^t0, small-error alphabet S_b0 = {-2^(b0-1),...,+2^(b0-1)-1}, integers n0,m0,b0,t0 such that k0=n0*t0+m0*b0 and m0*t0=2*k0. Honest classical PPT setup samples a **uniform public** A0 in (Z/q0Z)^(m0 x n0), binds exact row-major serialization and parameters into the claim domain, and publishes A0. A malicious choice A0=0 breaks this construction; genuine uniform setup and abort-safety remain explicit requirements, not proved by N-of-N rhetoric.

Parse a uniform k0-bit seed r as s0 uniform in (Z/q0Z)^n0 and e0 uniform in S_b0^m0 (offset the b0-bit chunks by -2^(b0-1)). Define G_A0(r) = LE_t0(A0*s0+e0 mod q0), exactly 2*k0 bits, split into ordered left/right k0-bit child seeds. For A0 uniform, the precise QPT-DLWE(n0,m0,q0,S_b0) challenge (A0,A0*s0+e0) versus (A0,U) is **exactly the single-generator pseudorandomness experiment**. Nothing is assumed about an unspecified iO/WE/WPRF or hidden-value release algorithm.

Starting with a freshly uniform hidden root r0, expand a complete binary tree to depth d using G_A0 at all internal nodes; concatenate the ordered 2^d leaf seeds. Choose target dimensions m1,n1,t1 with 2^d*k0=m1*n1*t1, and parse the output into target matrix A in (Z/2^t1Z)^(m1 x n1), little-endian t1-bit symbols in row-major order. Share A0 between independent claims but do NOT share r0. A0 is a genuine public common reference matrix, **not free** in resources.

Keep R49/R51's independent s1 uniform in (Z/2^t1Z)^n1, e1 uniform in S_b1^m1, K_bind uniform independent, and Y=A*s1+e1 mod 2^t1. For a pre-signed fixed-length L=m1*t1-bit ordinary native challenge signature sigma* on a canonical message binding ORIGINAL relation identity, actual SYS/BTC burn/authorization/output, claim/UTXO, branch, anchors/window, context, intended native verification key/path, A0 identifier, matrix commitment alpha, and R45 manifest, publish D=Encode(sigma*) XOR Encode_t1(Y). The signature, all preauthorizations and required off-chain witness/DA data must exist before irreversible funding under R45's conditional graph assumptions. Native Bitcoin PQ signature/no-EC-key-path functionality is NOT claimed deployed.

Compile the actual ORIGINAL NP verifier (off-chain) into the faithful public R46 Boolean quotient, with W_x spanned by genuine-witness-vanishing failure products and canonical P_x, S_x. For every bit mu of r0 || Encode(s1,e1) || K_bind sample independent bounded coefficient noise eta_mu and publish Z_mu=P_x(Delta*mu*1+eta_mu) over an odd source field, Delta=(qsrc-1)/2, M*B<Delta/2. Publish alpha=SHA3-384(domain||canonical A0 identifier||canonical A), and CK=F(K_bind,x,alpha,A0,exact challenge message,vk_native,Z,D,context,related-public-fields). Public auxiliary information must be exactly computable from those public fields, K_bind and independent coins; no extra target r0,s1,e1, native signing secret, signature or SOURCE-noise leakage. Hash binding of alpha is separately conditional on QPT collision resistance and canonical serialization.

OPEN(x,w) first verifies the **actual ORIGINAL R(x,w)=1 off chain**. It evaluates Ev_w(S_x(Z_mu)), nearest-center-decodes the complete secret root, pad seed and K_bind, recreates A and checks alpha and CK/context, derives Y and sigma* from D, checks the exact native signature on the intended challenge message, and returns **only that ordinary native signature**. Bitcoin executes no ORIGINAL verifier, general-purpose VM, PCP, Kilian/BitVM proof dispute or trace. The optional keyless Build, malicious-abort ceremony and full one-honest N-of-N graph proof remain unfinished.

## All-ORIGINAL-witness pointwise correctness

For any valid ORIGINAL witness w, Ev_w annihilates W_x, hence Ev_w(S_x(P_x(Delta*mu*1+eta_mu))) = Delta*mu+Ev_w(eta_mu). The M*B noise bound guarantees the **same Build-selected bits** for every valid w. All valid witnesses therefore recover the identical root r0, A, pad seed, K_bind and precommitted native signature, without canonical witnesses, matching internal states, or an assumed SourceOpen oracle. This proves correctness under honest Build, NOT hard-TRUE secrecy.

## QPT tree lemma with a shared public A0

Let H_i independently sample all 2^i k0-bit seeds at tree level i and apply real G_A0 recursively below that level, for 0<=i<=d. H_0 is the real matrix-bitstream and H_d is uniformly random. In H_i -> H_(i+1), replace 2^i independent uniform node outputs G_A0(U_k0) with independent U_2k0 one at a time. For each replacement the reduction receives **one actual LWE challenge (A0,Y)**, uses the given A0 to generate all other honest nodes and independent non-target claims, substitutes Y at the chosen node, and computes every descendant subtree from Y. The node seed need not be recovered. The public A0 is the SAME for all nodes: no invalid fresh-matrix assumption. A straight-line arbitrary-QPT adversary processes the entire resulting classical public data coherently. Telescoping and the QPT-DLWE game give

Adv_QPT(tree-vs-uniform) <= (2^d-1) * Adv_QPT-DLWE_base

for efficient simulatable advice/opening records, no rewinding, programmable QROM, generic group, or postulated witness-release property. At depth 11 the explicit hybrid loss is 2047. This bound is not a concrete 128-bit security estimate.

## Exact restricted full-public certified-FALSE composition

Fix an unopened **certified-FALSE** target whose public algebraic certificate gives 1 in W_x, so P_x(1)=0, and assume this certificate/truth is invariant as alpha and A0 change across challenge hybrids. Its complete target SOURCE capsule vector is exactly P_x(eta), **independent of all target root/pad bits**. Hence a PRG-tree LWE challenger can supply A0 and its challenge Y at any internal node and the reduction computes the actual matrix, alpha, x, every target SOURCE capsule without unknown root, CK with the independently chosen K_bind, D with its known target native signature and own pad seed, all permitted aux and independent related openings. In the real branch the FULL joint target view is exact; in the random branch A is uniform.

Next use ordinary QPT-DLWE_pad for the independently uniform A: given (A,Ypad), the reduction constructs the exact entire SOURCE P_x(eta), CK, context, aux, and D=sigma* XOR Encode(Ypad) **without s1,e1**. In the uniform-Ypad branch D is uniform and independent of sigma*. An ordinary native QPT-EUF-CMA reduction can therefore simulate the whole view without target signing secret or target signature and use any accepted signature on the fresh bound challenge message as a native forgery. For this explicitly restricted class:

Pr[accepted target signature in REAL certified-FALSE game] <= (2^d-1)*Adv_QPT-DLWE_base + Adv_QPT-DLWE_pad + Adv_QPT-EUF_native.

Exact complete-seed recovery also yields a valid signature. QPT collision resistance is a *separate* requirement for adversarial mutation of alpha, and target-message distinctness is mandatory. Allowed coherent non-target opening tables are fully simulated because they are independent and known; no target opening, same-root sibling opening, arbitrary target-correlated quantum advice, or full coherent precommit selective-opening model is proved. R44's target-guessing penalty is separate for its classical adaptive selection game. This proof is NOT arbitrary-FALSE IND, arbitrary TRUE security, secret extraction, or malicious setup security.

## Resource accounting, finite checks and status

Illustrative ONLY, without justified 128-bit estimates: base q0=2^16,n0=256,m0=1024,b0=4,k0=8192, base output 16384 bits; depth d=11 yields 2048 leaf seeds = 16,777,216 bits, exactly one target m1=4096,n1=256,t1=16 LWE matrix. Generation requires 2047 public-A0 matvecs (about 536 million modular multiply-adds); this is expensive and not a demonstrated practical speedup. A0 itself costs 524,288 bytes. At illustrative ORIGINAL TRUE quotient codimension 15 with 3 bytes/coefficient: encrypted root+pad+K_bind = (8192+20480+256)*45 = 1,301,760 bytes. Add 8192-byte masked signature, 48-byte matrix commitment and the public A0: ONE claim totals **1,834,288 bytes**, 39.63% below R49's 3,038,464 but **92.50% above** R51's 952,880 SHAKE-hypothesis variant. With eight independent claims sharing A0, per-claim cost is 1,375,536 bytes (before source basis/graph/evidence). This is a *premise improvement*, not an overall better size than R51, not practical parameter validation.

The exact embedded JavaScript checker below was executed **twice with identical output** using Node 22: 2,949 finite assertions, 512 openings for two distinct TRUE ORIGINAL witnesses on each of 256 toy root seeds, 64 certified-FALSE source couplings, a genuine toy modular-LWE tree, and exact resource arithmetic. A separate extended local JavaScript checker executed twice identically with 11,087 finite assertions, SHA3-384 CK/aux toy checks, and the same 512/64 fixture counts. The toy LWE is **insecure**; no QPT security is tested.

**Exact unresolved next equation.** For arbitrary hard-TRUE ORIGINAL x, P_x(1) is nonzero, and root/pad SOURCE capsules remain correlated with unknown challenge secrets. Nothing above simulates that full view or proves arbitrary unauthorized capability recovery/native forgery -> an **ACTUAL ORIGINAL witness** or independent QPT break. The indispensable target is
Pr[A_QPT gets bound native capability or accepted target signature | full hard-TRUE joint view] <= Pr[Ext^A outputs actual w with R_ORIGINAL(x,w)=1] + Adv_QPT(independent break) + negl.
No internal representation volunteering is permitted. R35/R46 short pseudoevaluation, R47 public dual, arbitrary-FALSE, malicious one-honest setup/abort, chain censorship/DA, and conditional Bitcoin PQ endpoint remain unresolved. **Do not disable ongoing research.**

## Exact executed checker

```javascript
// Executed R52 finite checker; all LWE dimensions here are unsafe toys.
let count=0, opened=0, coupled=0;
const assert=(v,m)=>{if(!v)throw Error(m);count++};
const same=(a,b,m)=>assert(JSON.stringify(a)===JSON.stringify(b),m);
const q=257, mod=(v,p)=>((v%p)+p)%p;
const bits=(v,k)=>Array.from({length:k},(_,i)=>(v>>>(k-1-i))&1);
const num=b=>b.reduce((a,v)=>2*a+v,0);
const indicator=v=>{let a=Array(8).fill(0);a[0]=1;for(let j=0;j<2;j++){
let t=Array(8).fill(0);for(let i=0;i<8;i++)if(v>>j&1)t[i|1<<j]+=a[i];else{t[i]+=a[i];t[i|1<<j]-=a[i]};a=t;}return a};
function source(forbidden){let rows=forbidden.map(indicator),piv=[],h=0;
for(let j=0;j<8;j++){let r=rows.findIndex((v,i)=>i>=h&&mod(v[j],q));if(r<0)continue;
[rows[h],rows[r]]=[rows[r],rows[h]];let inv=1;while(mod(rows[h][j]*inv,q)!==1)inv++;
rows[h]=rows[h].map(v=>mod(v*inv,q));for(let k=0;k<rows.length;k++)if(k!==h){let s=rows[k][j];rows[k]=rows[k].map((v,i)=>mod(v-s*rows[h][i],q))};piv.push(j);h++;}
let free=Array.from({length:8},(_,i)=>i).filter(v=>!piv.includes(v));
function P(v){v=v.map(x=>mod(x,q));for(let i=0;i<h;i++){let a=v[piv[i]];v=v.map((x,j)=>mod(x-a*rows[i][j],q))}return free.map(j=>v[j])}
function ev(z,w){let a=Array(8).fill(0);free.forEach((j,i)=>a[j]=z[i]);return mod(a.reduce((s,v,j)=>s+((j&~w)===0?v:0),0),q)}
return {P,ev,enc:(b,e)=>{let v=e.slice();v[0]+=128*b;return P(v)},dec:(z,w)=>{let v=ev(z,w);return +(Math.min(mod(v-128,q),mod(128-v,q))<Math.min(v,q-v))},rank:h};}
const T=source([0,1,2]),F=source([0,1,2,3]);same([T.rank,F.rank],[3,4],'source ranks');same(F.P([1,0,0,0,0,0,0,0]),[0,0,0,0],'FALSE constant mask');
const A0=[3,5,7,11],G=root=>{let s=num(root.slice(0,4)),e=root.slice(4).map(x=>x-1);return A0.flatMap((a,i)=>bits(mod(a*s+e[i],16),4))};
function tree(root){let a=[root];for(let k=0;k<3;k++)a=a.flatMap(s=>{let v=G(s);return [v.slice(0,8),v.slice(8)]});return a.flat()}
function matrix(root){let b=tree(root);assert(b.length===64,'64-bit matrix');return Array.from({length:4},(_,i)=>Array.from({length:4},(_,j)=>num(b.slice((i*4+j)*4,(i*4+j+1)*4))))}
const s=[2,4,7,12],e=[-1,0,0,-1],bind=[1,0,1,0],sig=bits(0xa5c3,16);
const eta=i=>Array.from({length:8},(_,j)=>mod(i*5+j*7,3)-1);
const pad=A=>A.flatMap((row,i)=>bits(mod(row.reduce((v,a,j)=>v+a*s[j],0)+e[i],16),4));
for(let n=0;n<256;n++){let r=bits(n,8),A=matrix(r),seed=[...r,...s.flatMap(v=>bits(v,4)),...e.map(v=>v+1),...bind];
let Z=seed.map((v,i)=>T.enc(v,eta(i+41*n))),D=pad(A).map((v,i)=>v^sig[i]);
let CK=JSON.stringify(['bound',bind,A,Z,D]);for(let w of [3,7]){let openedSeed=Z.map(z=>T.dec(z,w));same(openedSeed,seed,'all original witnesses same seed');
same(matrix(openedSeed.slice(0,8)),A,'rebuild A');same(pad(A).map((v,i)=>v^D[i]),sig,'precommitted capability');
same(JSON.stringify(['bound',openedSeed.slice(-4),A,Z,D]),CK,'secret-bound CK');opened++;}}
for(let n=0;n<64;n++){let a=bits(n,8),b=bits(255-n,8),x=[...a,...bits(9,4)],y=[...b,...bits(9,4)];
let noise=x.map((_,i)=>eta(1000+i+31*n));same(x.map((v,i)=>F.enc(v,noise[i])),y.map((v,i)=>F.enc(v,noise[i])),'FALSE seed-independent capsules');
same(x.map((v,i)=>F.enc(v,noise[i])),noise.map(F.P),'FALSE simulator');coupled++;}
same([256*16+1024*4,1024*16],[8192,16384],'base LWE generator exact doubling');
same([8192*2048,2048-1],[4096*256*16,2047],'full matrix and QPT hybrid node count');
same(28928*45+8192+48+524288,1834288,'full one-claim public CRS cost');
console.log(JSON.stringify({run:'R52-LWE-TREE-ORIGINAL-MATRIX-20261103',assertions:count,original_openings:opened,certfalse_couplings:coupled,full_hybrid_nodes:2047,bytes_one_claim:1834288,QPT:'NOT TESTED',hard_TRUE_extraction:'UNPROVED'}));
```

## Exact captured output (two identical executions)

```json
{"run":"R52-LWE-TREE-ORIGINAL-MATRIX-20261103","assertions":2949,"original_openings":512,"certfalse_couplings":64,"full_hybrid_nodes":2047,"bytes_one_claim":1834288,"QPT":"NOT TESTED","hard_TRUE_extraction":"UNPROVED"}
```
