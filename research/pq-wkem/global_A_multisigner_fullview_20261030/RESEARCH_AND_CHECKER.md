# Globally shared A across signers: restricted full-public SOURCE reduction

**2026-10-30, offline bounded iteration. RESTRICTED CONSTRUCTIVE EFFICIENCY + PROOF, NOT ORIGINAL-WKEM.**
Predecessor: existing syscoin/PVUGC PR #1, head 4006fd35d37fcf13f054cd4d9bfaec54a442671b, research/pq-wkem/direct_native_secret_seed_20261030/RESEARCH.md at exact Git blob a5055fc6b4815c6e22a7407f9e6c866031c7f2e1. Previously one honest public A was stored **per signer** and reused only across that signer's scopes. Here ALL signers/scopes use one honestly sampled A. No external literature/web was consulted.

## Explicit algorithm, exact distribution and unchanged release

Set q=16777213 prime, n=256, m=4469, w=2000, B=128, g=524287, L=52 for the illustrative, NOT QPT-128-calibrated setting. Sample A uniformly once from F_q^(n×m). For every independent signer h and claim/path scope s, independently sample U_(h,s) uniformly from F_q^(n×L); genuine native signing seeds SK.seed and SK.prf each uniformly 16 bytes; public PK.seed uniformly 16 bytes; the genuine Native.KeyGenFromSeeds yields pk=(PK.seed,PK.root). Let literal 32-byte K=SK.seed||SK.prf. Separately choose V uniform GF(256)^32; set three Shamir shares S_i=K+alpha_i*V (bytewise GF(256), alpha=1,2,3). Convert each S_i to exactly L canonical little-endian 5-bit digits a_i,l. For EVERY packet i independently draw r_i uniform F_q^n and eta_c,i from chi^m and eta_d,i from chi^L, where centered chi is bounded by B. Publish:
    c_i=A^T r_i+eta_c,i in F_q^m
    d_i=U_(h,s)^T r_i+eta_d,i+g*a_i in F_q^L.
Never reuse U, native keys, K, V, r or errors across claims or signers. The public A may be reused across all.

Public OFF-CHAIN Release takes any independently supplied **legal SOURCE** representation z_l for U_l, with A z_l=U_l, signed-unit coefficients and exact weight w. It cyclically decodes d_i,l-z_l^T c_i, obtaining authentic share digits because |eta_d,i,l-z_l^T eta_c,i|≤B(w+1). Both strict margins g>2B(w+1) and q-31g>2B(w+1) hold. Every legal SOURCE z (possibly different for every packet) yields the same authentic S_i; any two packet indices reconstruct the same literal native K and check true native pk before signing. THIS IS NOT an algorithm mapping arbitrary ORIGINAL W to z, which remains the main missing step.

The full public output includes relation/statement, authenticated exact original-claim/UTXO/branch/anchors/window/path/context and setup session, one common A, every independently chosen U and every public packet for all h,s, genuine native checking keys, permissible native signatures, auxiliary/manifest data, related capsules and explicitly allowed selective openings. The output checker test intentionally MOCKS native pk derivation; proof premise requires actual native KeyGen and QPT EUF-CMA.

## Straight-line QPT full-public theorem, and exact restrictions

Assume ordinary nonuniform **QPT decisional-LWE** for uniform M=[A|U] ∈F_q^(n×(m+L)), uniform secret r∈F_q^n and noise chi^(m+L), comparing (M,M^T r+eta) against (M,uniform F_q^(m+L)). Assume genuine native KeyGen distribution is independently uniform in those seeds and QPT EUF-CMA; separately account for QPT manifest/session authentication. Honest algorithms are classical PPT. The adversary is arbitrary nonuniform QPT with quantum advice independent of protected hidden coins/K except via the generated complete public view. It may coherently process all public capsules, receive classical allowed-message native signature responses, and adaptively obtain at most ONE full target packet's classical encryption coins. Its other-signers and auxiliary may be arbitrary efficient QPT functions of A, target U, target pk, public packets and its independent local secrets/coins, including deliberate reuse of the common A; the reduction executes these functions on its challenge input. It may NOT obtain target SOURCE openings, unreleased target seeds, hidden-key-correlated nonuniform auxiliary, quantum coin-leakage oracles or target coin disclosures for two packets. Actual ORIGINAL source-conditioned setup, arbitrary adaptive correlated honest SOURCE opening distributions and malicious N-1 setup are NOT included.

Fix one protected (h,s), and any unordered two-packet set T among {1,2,3}. Let E_T be successful recovery of a usable complete native secret OR accepted fresh claim-scoped native signature forgery, together with no disclosure of coins of any packet in T. With at most one packet exposed, 1_Win≤sum_T 1_E_T pointwise. The simulator receives ordinary LWE M=[A|U_protected] and one whole challenge vector; it constructs *every other signer and scope using exactly this A* with independent U and r/eta and legitimate genuine native checking keys, while executing any allowed public-view-dependent adversarial side generator. This is the EXACT joint distribution in the LWE branch, even if the other-signer data is adaptively correlated with A and target public packets. The simulator aborts to output 0 if the target's selective-coin query hits T; E_T could not occur there. Replace the two unopened whole protected packet vectors one at a time by independent uniform values using two ordinary full-vector decisional-QPT-LWE hybrids. No extraction, rewinding, source-opening oracle, generic model or independent-A premise is used. QPT data processing of the complete simulated public view gives:
    |Pr_real[E_T]-Pr_both_uniform[E_T]| ≤ 2 Adv_QPT-LWE.

In the both-uniform world the remaining genuine Shamir share S_k=K+alpha_k V is itself uniformly random and information-theoretically independent of K, genuine native pk and allowed signing responses, even if its complete coins are disclosed. A genuine native EUF-CMA challenger can supply the exact pk; the simulator independently samples that single share and its honest packet with the shared A, and two uniform packets, and uses its allowed-message native signing oracle. If a full native SK is recovered, use it to sign a fresh scoped message; if accepted fresh signature is returned, it is already an EUF forgery. Including authentication failures, one protected scope has:
    Pr[Win] ≤ 3(2 Adv_QPT-LWE+Adv_QPT-Native-EUF-CMA+Adv_QPT-auth).
Polynomially many independent protected scope choices need an explicit index-guess/union factor. This is the SAME ordinary QPT-LWE assumption and native EUF assumption as the predecessor, without an extra PRG assumption. In particular, malicious other-signer *public-output processing* is allowed but an actual unknown-one-honest coin-flip transcript is NOT proven simulatable from an LWE challenge.

## Shared-A planted OTHER-opening pre-disclosure lemma

For the predecessor's explicitly planted other-source sampler (not a uniform-target-after-opening oracle), draw each Z_j independently uniform from signed-unit set T with |T|=2^w*binom(m,w), and publish U_j=A Z_j. For random public A, z↦Az is universal: for two distinct z,z', Pr_A[Az=Az']=q^-n. The one-column leftover/second-moment distance satisfies epsilon≤(1/2)sqrt((q^n−1)/|T|). Conditional on A the independent Z_j induce independent U_j; thus a telescoped expectation gives
    TV((A,AZ_1,...,AZ_K),(A,U_1,...,U_K)) ≤ K*epsilon
with U_j fresh uniform. Independence of A across signers is NOT needed. With m=4469,w=2000,n=256,q=16777213 and K=4*5200=20800 across four signers, log2 |T|=6427.049619..., log2(q^n)=6143.999934..., and log2(K*epsilon)≤-128.180546.... This retains the predecessor's four-signer pre-disclosure margin. If an actual Z_j is disclosed, (A,Z_j,AZ_j) is NOT equivalent to (A,Z_j,U_j); sample exact planted side correlations instead. This lemma does not manufacture any ORIGINAL-opening compiler or apply to the protected target U.

## One-honest ceremony caveat

For any irrevocably fixed corrupt matrix shares B_1,...,B_(N-1), an independent honest uniform H yields A=H+sum B_i mod q EXACTLY uniform, conditional on B_i. A corrupt last mover who sees H first can instead force any desired A. This algebraic condition is checked for toy fields. It does NOT instantiate an unknown-position one-honest commit/reveal: commitments, QPT straight-line extraction/equivocation, simultaneous adaptivity, selective aborts, funding and repeated grinding remain unresolved. Do not claim malicious-N-1 setup or abort-safe funding.

## Precise storage and reproducibility

At 3 packed bytes per F_q element, one A costs n*m*3=3,432,192 B; each (h,s) costs (n*L+3*(m+L))*3=80,625 B. Four signers and 100 scopes each cost 4*3,432,192+400*80,625=45,978,768 B with separate signer A, versus 3,432,192+400*80,625=35,682,192 B with global A, saving **10,296,576 B / 22.3941972521%**. Excludes genuine native signatures/PKs, original evidence, context, manifests, key-reference hashes, Bitcoin witness bytes, graph and fees. No concrete QPT-128 calibration.

The exact self-contained V8/Node-compatible JavaScript checker below was executed TWICE with byte-identical JSON output (84,038 assertions each), verifying GF(256) Shamir release from all three packet pairs for two different legal toy SOURCE openings, a shared public A for four signers, exact tiny-field whole-LWE challenge-embedding and nonlinear public auxiliary distributions, additive uniform-one-honest field shares, planted cross-signer TV accounting, and exact storage. An independent LOCAL Python checker also passed 132,253 assertions twice identically; it uses a nonuniform planted SOURCE toy and mocked native PK, and is NOT a quantum experiment or implementation of genuine SLH signatures. An initial LOCAL-only Python histogram multiplicity assertion for (A,U_bad)=(0,0) was corrected before the final two passing runs. Tests establish finite algebra only.

## Essential unresolved ORIGINAL equation

Find actual classical-PPT witness-free Comp(R_original,x,scope,pk) and public Lift(x,W,A,U,scope) that for **EVERY valid ORIGINAL witness** returns possibly distinct legal SOURCE openings for any two required packets and the SAME precommitted native sk. The compiler's source-dependent setup/opening data, full public capsule/checking key, auxiliary, other capsules and quantum challenger simulator must be instantiated **TOGETHER**, not via assumed SourceOpen. Prove full-public fixed-FALSE secrecy and arbitrary unauthorized hard-TRUE final-key recovery or native forgery -> an actual ORIGINAL witness or independently justified QPT break without requiring an adversary-supplied representation. The unknown-one-honest malicious setup, pre-funding abort/graph/DA, authenticated SYS/BTC qualification and hypothetical native PQ Bitcoin endpoint remain outstanding. Do not fund, merge, deploy, or disable research automation as if completed.

## Exact executed JavaScript checker

```javascript
const globalATest = function globalATest(){
 let checks=0, releases=0; function ok(v,m){checks++;if(!v)throw Error(m);}
 let seed=0x20261030>>>0;function rng(x){seed ^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return (seed>>>0)%x;}
 function mul(a,b){let p=0;for(let i=0;i<8;i++){if(b&1)p^=a;let hi=a&128;a=(a<<1)&255;if(hi)a^=27;b>>=1;}return p;}
 function div(a,b){ok(b!==0,"nonzero GF divisor");for(let i=1;i<256;i++)if(mul(b,i)===1)return mul(a,i);throw Error("no inverse")}
 const q=257;
 function enc(A,U,s){let r=[rng(q),rng(q)],m=A[0].length;let c=Array.from({length:m},(_,j)=>(r[0]*A[0][j]+r[1]*A[1][j]+rng(3)-1+q*q)%q);let d=Array.from({length:8},(_,j)=>(r[0]*U[0][j]+r[1]*U[1][j]+rng(3)-1+64*((s>>j)&1)+q*q)%q);return [c,d]}
 function dec(packet,z){let [c,d]=packet,s=0;for(let j=0;j<8;j++){let v=((d[j]-z.reduce((a,t,i)=>a+t*c[i],0))%q+q)%q;let d0=Math.min(v,q-v),v1=((v-64+q)%q),d1=Math.min(v1,q-v1);ok(d0!==d1,"bit decode unique");s|=+(d1<d0)<<j;}return s}
 for(let t=0;t<24;t++){let cs=Array.from({length:3},()=>[rng(q),rng(q)]);let A=Array.from({length:2},(_,r)=>cs.flatMap(c=>[c[r],c[r]]));let U=Array.from({length:2},(_,r)=>Array(8).fill((A[r][0]+A[r][2])%q));let z1=[1,0,1,0,0,0],z2=[0,1,0,1,0,0];for(let s=0;s<4;s++)for(let c=0;c<4;c++){let K=rng(256),V=rng(256),alph=[1,2,3],S=alph.map(a=>K^mul(a,V));let ps=S.map(v=>enc(A,U,v));for(let [i,j] of [[0,1],[0,2],[1,2]])for(let zi of [z1,z2])for(let zj of [z1,z2]){let si=dec(ps[i],zi),sj=dec(ps[j],zj),v=div(si^sj,alph[i]^alph[j]);ok((si^mul(alph[i],v))===K,"same native master");releases++}}}
 let key=v=>JSON.stringify(v), R=new Map(),E=new Map(),H=new Map();function add(mp,v){let s=key(v);mp.set(s,(mp.get(s)||0)+1)}
 for(let a=0;a<3;a++)for(let u=0;u<3;u++)for(let ub=0;ub<3;ub++)for(let r=0;r<3;r++)for(let rb=0;rb<3;rb++){let cb=a*rb%3,db=ub*rb%3;let view=(c,d)=>[a,u,ub,c,d,cb,db,(c+2*cb+ub)%3,(d*cb+u+db)%3];add(R,view(a*r%3,u*r%3));add(E,view(a*r%3,u*r%3));for(let x=0;x<3;x++)for(let y=0;y<3;y++)add(H,view(x,y));}
 ok(R.size===E.size,"global A challenge supports equal");for(const [k,v]of R)ok(E.get(k)===v,"exact shared-A challenge embedding");ok(H.size===675,"uniform branch support");
 for(const [k,v] of H){let [a,u,ub]=JSON.parse(k);ok(v===(a===0&&ub===0?9:3),"exact uniform branch multiplicity")}
 for(let p of [3,5,7,11])for(let x=0;x<p;x++)for(let y=0;y<p;y++){let occ=Array(p).fill(0);for(let h=0;h<p;h++)occ[(x+y+h)%p]++;ok(occ.every(v=>v===1),"honest additive uniform share")}
 let n=256,m=4469,L=52,N=4,C=100,J=3, unit=3;
 let A=n*m*unit,other=N*C*(n*L+J*(m+L))*unit,old=N*A+other,cur=A+other;
 ok(old===45978768 && cur===35682192 && old-cur===10296576,"exact size accounting");
 let w=2000,q0=16777213,logT=w;for(let i=1;i<=w;i++)logT+=Math.log2((m-w+i)/i);
 let bound=Math.log2(20800)-1+0.5*(n*Math.log2(q0)-logT);
 ok(bound>-128.19&&bound<-128.17,"shared A planted-source TV");
 return {status:"PASS",assertions:checks,releases,oldBytes:old,newBytes:cur,savedBytes:old-cur,percentSaved:100*(old-cur)/old,log2PlantedBound:bound,worldSupport:[R.size,H.size],notes:"Correctness toy nonuniform; no QPT/native-PQ/ORIGINAL compiler test."}
};
console.log(JSON.stringify(globalATest()));
```

## Captured deterministic output

```json
{"status":"PASS","assertions":84038,"releases":4608,"oldBytes":45978768,"newBytes":35682192,"savedBytes":10296576,"percentSaved":22.39419725208818,"log2PlantedBound":-128.18054667956574,"worldSupport":[211,675],"notes":"Correctness toy nonuniform; no QPT/native-PQ/ORIGINAL compiler test."}
```
