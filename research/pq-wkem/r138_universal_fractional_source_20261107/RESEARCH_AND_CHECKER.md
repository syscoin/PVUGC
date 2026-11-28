# R138 — Universal fractional-source bypass of complement-pair dual-LWE

**Status:** REJECTED original-dependent release family; a structural strengthening of R137's longer-integer false-source attack. This is not a secure witness-KEM or a constructive repair. No external research or efficiency optimization.

**Provenance:** syscoin/PVUGC PR #1, open/draft/unmerged, research/pq-wkem-validation-20260918, initial head a11d46ba76d86c359ecb56a95004d812b620b279. Exact R137 file blob 6eba9ad15643b397b8753443577c28f8637ca0c9; most recent substantive ordinary PR comment 6698876958. One subproblem only: can a noise threshold or coding enforce the short Boolean certificate before the public dual-LWE phase reveals the same capability?

## Exact original-dependent source and release

Let x be any ORIGINAL 3-CNF with n Boolean variables and m clauses, each with exactly three literal occurrences. Put B=n+2m. For every variable and for two slack bits per clause, form a pair (z_i0,z_i1), with z_i0+z_i1=1. Define H_x z=b_x by these B pair equalities and one equation per clause:

sum of three signed literal coordinates - z_pj0 - z_qj0 = 1.

Each satisfying Boolean assignment gives a distinct z_w with H_x z_w=b_x, ||z_w||_1=B and ||z_w||_2 squared=B. Every ORIGINAL witness should recover the same precommitted key/capability K. False x has no Boolean certificate; the earlier supplied-integer shortness lemma remains valid but does not restrict public recovery.

The attempted source samples s uniform in Z_q^(B+m), independent e_i uniform in [-E,E], eta uniform in [-E0,E0], and publishes A=H_x mod q, u=b_x mod q, c=A^T s+e, d=u^T s+Delta*K+eta mod q. Full J/CK/Aux, claim/UTXO/branch/anchors/window/context, VK and related capsules are public. Honest off-chain Open uses any valid original witness to compute d-z_w^T c = Delta*K+eta-z_w^T e. A sufficient uniform decoding condition is Delta>2M, where M=E0+EB, with q large enough to prevent aliasing.

## Universal counterfeit for every 3-CNF, including hard FALSE instances

Without solving x, publicly set each input-variable complement pair to (1/2,1/2) and each of the two per-clause slack complement pairs to (1/4,3/4). Call the rational vector zbar. Every literal equals 1/2, so every clause linear equation becomes 3/2-1/4-1/4=1, for EVERY x independent of satisfiability:

H_x zbar=b_x; ||zbar||_1=B; ||zbar||_2 squared=n/2+5m/4 < n+2m=B.

Let Z=4zbar; Z is a publicly computable integer vector whose coordinates are 1,2,3. The attacker does not provide a representation to any verifier. It computes on the ACTUAL public ciphertext:

P=4d-Z^T c=4 Delta K+4eta-Z^T e (mod q).

The normalized fake noise satisfies |eta-zbar^T e|<=E0+EB=M on every tape, precisely the same worst-case noise budget as a genuine Boolean witness. If Delta>2M and q>4Delta+8M, the public fake phase perfectly decodes K on EVERY allowed noise tape, even when the ORIGINAL statement is FALSE. Both q and Delta can be polynomial in n+m. Neither ordinary decisional QPT-LWE nor native EUF-CMA is broken; the statement-dependent A is not a uniform LWE matrix, and a public affine identity bypasses the intended gate. Sibling capsules and CK/Aux computed from these ciphertexts cannot prevent this direct public recovery.

A concrete false witness-free statement is x=(v OR v OR v) AND (NOT v OR NOT v OR NOT v), n=1,m=2,B=5. The fake Z=(2,2,1,3,1,3,1,3,1,3), norm1(zbar)=5, norm2(zbar)^2=3. With q=257, Delta=16, E=E0=1, M=6, the conditions hold (16>12 and 257>112), and K is recovered from every noise tape. This defeats the attempted threshold repair, which had hoped to reject R137's invalid INTEGER representation with norm1=7.

## Separate exact probabilistic channel check for independent-share repair

At q=257, Delta=8, the all-tape criterion is not met, but each independently hard-decoded fake phase has *lower* binary crossover than honest Boolean phase at B=5. With ternary uniform errors and independently randomized nearest-codepoint ties:

p_honest=35/1458; p_fake=1001/177147; p_fake<p_honest.

The fake BSC can be degraded EXACTLY to the honest BSC by injecting extra independent flips with probability alpha=(p_honest-p_fake)/(1-2*p_fake)=6503/350290. Thus no statement-independent outer coding, XOR sharing, or error-correction design acting only on these independent hard-decoded bit outputs can make the honest channel reliable while hiding from this fake channel. This is NOT Blackwell dominance of complete soft phases and NOT a theorem for all parameters or statement-dependent codes.

For uniform ternary error, f(t)=log((1+2cosh(t))/3) is convex and f(0)=0. For each a in [0,1], f(a*t)+f((1-a)*t)<=f(t). Applying per complement pair proves the fake normalized residual has no larger exponential moment than the honest Boolean residual for all real t. This is moment domination, NOT full tail stochastic dominance.

## Exact limits and handoff

This is an explicit classical PPT false-instance release attack against the whole R137 linear complement-pair class in the stated no-wrap margin regime. Therefore no arbitrary QPT full-public false-source security theorem or unauthorized recovery-to-ORIGINAL-witness extraction can hold for this source. An ORIGINAL-dependent nonlinear Booleanity-enforcing release MUST prevent extension to the universal public rational zbar; merely checking Booleanity or shortness in honest Open does nothing. The needed next construction must jointly instantiate genuine source keys/opening data and standard-QPT-assumption challenge simulation for (R,x,C,J,CK,Aux,VK,context,related capsules), and reduce any unauthorized QPT recovery or accepted native forgery to an ACTUAL ORIGINAL witness or independently justified QPT break. The N-of-N graph, malicious setup/abort, multi-capsule selective-opening proof, native PQ endpoint and PQ calibration remain unproved. The candidate is rejected; no optimization justified.

## Executed checker, captured output and provenance

The JavaScript below was actually executed in the connected V8 runtime before creating Git objects: 2,640 successful assertions; 140 arbitrary varied-sign/repeated-literal 3-CNF fixtures; exhaustive 32 Boolean assignments to the displayed false example; 1,024 real public-phase samples with zero incorrect unauthorized decodes, using q=257, Delta=16. The universal algebra/no-wrap proof is analytic; finite tests are not QPT-hardness experiments.

An independent LOCAL-ONLY Python checker ran twice with identical JSON and verified the exact ternary error PMFs, exact BSC degradation, 140 general 3-CNF identities, 23 Delta thresholds and 4,096 actual modular samples at Delta=8 (4,077 unauthorized recoveries). Python source SHA-256: 35890bb05d92ca14e104cfa15daeb9bbab33ee429c1f330e48c906af8531f162; captured local JSON SHA-256: c34e1440bf0ce9534886ec5af86e1a80bfee8d0ba40343960f50c0aba8126941. Those scripts are local-only, not part of this GitHub commit.

~~~javascript
const Q=257,delta=16;let checks=0;const ck=(v,m)=>{checks++;if(!v)throw Error(m)};
const dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
function comp(n,clauses){const B=n+2*clauses.length,D=2*B,H=[],b=[];
 for(let i=0;i<B;i++){let r=Array(D).fill(0);r[2*i]=r[2*i+1]=1;H.push(r);b.push(1)}
 for(let j=0;j<clauses.length;j++){let r=Array(D).fill(0);for(let [v,neg] of clauses[j])r[2*v+neg]++;
 r[2*(n+2*j)]--;r[2*(n+2*j+1)]--;H.push(r);b.push(1)}
 return {B,H,b}};
function fractional(n,m){let z=[];for(let i=0;i<n;i++)z.push(2,2);for(let i=0;i<2*m;i++)z.push(1,3);return z}
for(let n=1;n<=4;n++)for(let m=1;m<=7;m++)for(let t=0;t<5;t++){
 const clauses=Array.from({length:m},(_,j)=>Array.from({length:3},(_,k)=>[(j+k+t)%n,(j+t+2*k)%2]));
 let {B,H,b}=comp(n,clauses),Z=fractional(n,m);
 ck(H.every((r,i)=>dot(r,Z)===4*b[i]),"universal scaled identity");
 ck(Z.reduce((v,x)=>v+x,0)===4*B,"l1 identity");
 ck(Z.reduce((v,x)=>v+x*x,0)===8*n+20*m,"l2 identity");
 ck((8*n+20*m)<16*B,"strict l2 gap");
}
const clauses=[[[0,0],[0,0],[0,0]],[[0,1],[0,1],[0,1]]];
let {B,H,b}=comp(1,clauses),Z=fractional(1,2);
for(let mask=0;mask<(1<<B);mask++){const zs=Array.from({length:B},(_,i)=>(mask>>i)&1).flatMap(x=>[x,1-x]);
 ck(!H.every((r,i)=>dot(r,zs)===b[i]),"false source rejects all Boolean assignments")}
let seed=1381107>>>0;const rnd=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};
const dist=(a,b)=>Math.min(((a-b)%Q+Q)%Q,((b-a)%Q+Q)%Q);
let bad=0, count=1024;
for(let k=0;k<count;k++){
 let s=H.map(()=>rnd(Q)),e=Z.map(()=>rnd(3)-1),eta=rnd(3)-1,K=rnd(2);
 let c=Z.map((_,j)=>(H.reduce((v,r,i)=>v+r[j]*s[i],0)+e[j])%Q);
 let d=(dot(b,s)+delta*K+eta)%Q;
 let phase=((4*d-dot(Z,c))%Q+Q)%Q;
 ck(phase===((4*delta*K+4*eta-dot(Z,e))%Q+Q)%Q,"public phase");
 let recovered=(dist(phase,4*delta)<dist(phase,0))?1:0;
 ck(recovered===K,"false-capability perfect recovery");bad+=recovered!==K;
}
text({run:"R138-UNIVERSAL-FRACTIONAL-3CNF",status:"REJECTED",assertions:checks,general_formula_fixtures:140,false_boolean_trials:32,public_false_trials:count,wrong_recoveries:bad,q:Q,delta:delta,denominator:4});
~~~

Captured executed output:

~~~json
{"run":"R138-UNIVERSAL-FRACTIONAL-3CNF","status":"REJECTED","assertions":2640,"general_formula_fixtures":140,"false_boolean_trials":32,"public_false_trials":1024,"wrong_recoveries":0,"q":257,"delta":16,"denominator":4}
~~~
