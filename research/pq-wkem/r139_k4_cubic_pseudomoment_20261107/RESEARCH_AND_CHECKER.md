# R139 — K4 parity false source survives a cubic Boolean-moment LWE lift

Status: REJECTED ORIGINAL-dependent release candidate; no positive secure witness-KEM advance. This run investigates one direct repair of R138's rational-mixing failure. No size optimization, external literature, or general impossibility claim.

## Exact provenance and subproblem

Repository syscoin/PVUGC, existing draft PR #1, branch research/pq-wkem-validation-20260918. Starting head bfd53e68efb3fd8ab5a3e7f4bb1d8f60de208bb9. Prior exact R138 file blob ab60fb64fe925a5bb23b4ef5fb61053a49826723. The previous linear complement-pair source admitted a universal public rational counterfeit. Here the candidate genuinely adds degree-three Boolean clause checks, rather than another threshold adjustment. The finite checker and printed output below are reproducible.

## ORIGINAL-dependent candidate, release and parameters

Take a simple 3-XOR CSP compiled exactly into 3-CNF. There are six ORIGINAL Boolean edge variables x_e on the K4 graph. Each of four vertices has three incident edges and one parity constraint XOR_(e incident to v) x_e = b_v. For each of the four violating assignments of its three edges, include the ordinary 3-CNF clause prohibiting that assignment. The Boolean circuit accepts exactly when all sixteen resulting clauses hold; no proof verifier is placed in Bitcoin.

For each subset S of the six variables with |S| <= 3, define phi_S(w) = product_(e in S) w_e, with phi_empty=1. There are N=1+6+15+20=42 coordinates. Expand every forbidden-local-assignment indicator f_(v,a)(w) = product_(e in star(v)) [w_e if a_e=1, else (1-w_e)] as a linear form in these multilinear monomial coordinates. Build a public integer matrix H of 17 rows and 42 columns: the first row selects phi_empty, and the remaining sixteen rows select the coefficients of f_(v,a). Put u=(1,0,...,0) in Z^17. For every real ORIGINAL satisfying w, H phi(w)=u.

An attempted additive-noisy LWE-style release samples s uniformly in Z_q^17, independent errors e_j uniformly in {-1,0,1} for 42 coordinates, and eta uniformly in {-1,0,1}. It chooses precommitted capability bit K uniformly in {0,1}; publishes H,u,c=H^T s+e (mod q), d=u^T s+Delta*K+eta (mod q), plus the bound relation/statement, VK, scope, context and all public CK/Aux and related capsules. This is a candidate STRUCTURED matrix, not ordinary uniform-matrix LWE; no standard-QPT-LWE security theorem may be invoked for this distribution. Set q=8191 and Delta=128. Honest Open, given any ORIGINAL Boolean satisfying w, calculates phi(w), obtains p=d-phi(w)^T c=Delta*K+eta-phi(w)^T e, and decodes nearest to 0 or Delta modulo q. Since ||phi(w)||_1 <= 42, |eta-phi(w)^T e|<=43, so all honest valid witnesses recover the SAME K on every allowed tape (Delta > 2*43, no wrap).

## Explicit globally inconsistent FALSE input and public pseudo-opening

Set charge b=(1,0,0,0). XORing all four vertex parity equations gives 0=1 because every edge occurs twice. Thus there is no ORIGINAL Boolean satisfying assignment; the corresponding 3-CNF is FALSE.

Define a PUBLIC rational pseudo-moment vector m indexed by all monomials S of size at most 3:
- m_empty=1.
- For any one edge, m_S=1/2.
- For any two distinct edges, m_S=1/4.
- For three edges that form the star at vertex v, m_S=1/4 if b_v=1 and m_S=0 if b_v=0.
- For any other triple, m_S=1/8.

For each vertex, the restriction to its star's coordinates matches the first three moments of the UNIFORM LOCAL distribution on the four parity-satisfying triples for its charge. Hence E_m[f_(v,a)]=0 for every one of sixteen forbidden local assignments. Globally these local distributions are incompatible, but that contradiction is not visible to the single degree-three feature vector. Consequently H m=u EXACTLY, despite no w with ORIGINAL(x,w)=1. Every coordinate of m is in [0,1], and ||m||_1=10, below the honest worst-case bound 42. Z=8m is an explicitly computable INTEGER vector. In fact every coordinate of Z is in {0,1,2,4,8}.

Using only the ACTUAL public capsule the attacker calculates p_fake=8d-Z^T c (mod q). Since HZ=8u, p_fake=8*Delta*K+8*eta-Z^T e. The normalized fake residual is eta-m^T e with absolute value <=1+||m||_1=11, smaller than the honest decoding bound. Even the conservative bound 43 gives a scaled residual <=344; 8*Delta=1024, q=8191, and q>8*Delta+16*43. Therefore nearest-codepoint decoding reveals K for EVERY allowed noise tape, including FALSE statements, with no hidden source opening, verifier query, auxiliary representation provided to an extractor, or quantum computation. This rejects the entire displayed linearized-cubic source, not ordinary LWE in general.

The same public fake can recover any independently encoded finite number of capability bits using separate source samples, and so can recover a masked preauthorized native signature in this model. Public J/CK/Aux, claim context and related capsules cannot repair an already publicly recovered K without changing the release model. A QPT reduction is impossible for this exact candidate because a classical polynomial-time adversary wins FALSE. Thus no extraction-to-ORIGINAL, malicious ceremony, selective-opening, or Bitcoin endpoint claims are made.

## Design consequence, strict scope, next unfinished equation

The R138 rational shortcut is not repaired by merely embedding cubic Boolean constraints into a polynomial-length vector whose source opening remains LINEAR in publicly combinable features. Local probability distributions can agree on all low-degree overlaps without arising from any global Boolean witness. Requiring phi(w) to be true monomials in the honest Open API is not enough: the public ciphertext permits any integer linear combination. This specific K4 family is an explicit local-versus-global false instance, NOT a no-go theorem for all polynomial degree, nonlinear ciphertext schemes, high-degree consistency, or standard-QPT-LWE-based witness encryption.

Next useful constructive departure: find a classical-PPT source whose ACTUAL public evaluation enforces globally consistent ORIGINAL assignments cryptographically, rather than only its honest opening API enforcing consistency. Instantiate the statement-dependent source keys and their QPT LWE challenge simulator jointly including J/CK/Aux/VK/related capsules. Prove every-valid-witness SAME-capability, FALSE full-view security and arbitrary hard-TRUE unauthorized recovery/native forgery -> actual ORIGINAL witness or independent QPT break. Do not assume extraction from an adversary-volunteered feature representation. Remain off-chain for original proof verification and retain honest-erasure N-of-N and pre-funding graph requirements. No efficiency work is justified.

## Exact executed V8 checker (standard ECMAScript, deterministic; no external dependencies)

~~~javascript
(function run139(){
 const q=8191,delta=128,E=1,E0=1;let checks=0;
 const ck=(ok,label)=>{checks++;if(!ok)throw Error("assertion "+checks+": "+label)};
 const edges=[];for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)edges.push([i,j]);
 const stars=Array.from({length:4},(_,v)=>edges.map(([a,b],i)=>a===v||b===v?i:-1).filter(i=>i>=0));
 const pop=n=>{let c=0;for(;n;n&=n-1)c++;return c};
 const masks=Array.from({length:64},(_,i)=>i).filter(x=>pop(x)<=3);
 const starMask=stars.map(s=>s.reduce((a,i)=>a|(1<<i),0));
 const cols=Object.fromEntries(masks.map((mask,j)=>[mask,j]));
 const field=b=>{
  const H=[Array(masks.length).fill(0)],u=[1];H[0][cols[0]]=1;
  for(let v=0;v<4;v++)for(let a=0;a<8;a++){
   if(pop(a)%2===b[v])continue;
   let p=new Map([[0,1]]);
   for(let k=0;k<3;k++){
    const bit=1<<stars[v][k],np=new Map();
    for(const [mask,c] of p.entries()){
     if((a>>k)&1)np.set(mask|bit,(np.get(mask|bit)||0)+c);
     else {np.set(mask,(np.get(mask)||0)+c);np.set(mask|bit,(np.get(mask|bit)||0)-c)}
    }p=np;
   }
   const row=Array(masks.length).fill(0);
   for(const [mask,c] of p.entries())row[cols[mask]]=c;
   H.push(row);u.push(0);
  }
  return {H,u};
 };
 const dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
 const bF=[1,0,0,0],F=field(bF),T=field([0,0,0,0]);
 const fake=masks.map(mask=>{const n=pop(mask);if(n===0)return 8;if(n===1)return 4;if(n===2)return 2;const v=starMask.indexOf(mask);return v<0?1:(bF[v]===1?2:0)});
 ck(edges.length===6&&stars.every(s=>s.length===3)&&masks.length===42,"dimensions");
 ck(F.H.length===17&&T.H.length===17,"constraints");
 for(let i=0;i<F.H.length;i++)ck(dot(F.H[i],fake)===8*F.u[i],"pseudomoment relation "+i);
 ck(fake.every(x=>x>=0&&x<=8),"fractional range");
 ck(fake.reduce((a,b)=>a+b,0)===80,"l1 numerator");
 let truthCount=0;
 for(let z=0;z<64;z++){
  const ph=masks.map(m=>(z&m)===m?1:0);
  const satisfies=f=>f.H.every((r,i)=>dot(r,ph)===f.u[i]);
  ck(!satisfies(F),"FALSE has no Boolean witness");
  if(satisfies(T))truthCount++;
 }
 ck(truthCount===8,"TRUE parity assignments");
 let seed=1391107>>>0;const rand=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};
 const mod=n=>(n%q+q)%q,dist=(a,b)=>{const d=mod(a-b);return Math.min(d,q-d)};
 const simulate=(f,v,scale)=>{
  const s=f.H.map(()=>rand(q)),e=v.map(()=>rand(3)-1),eta=rand(3)-1,K=rand(2);
  const c=v.map((_,j)=>mod(f.H.reduce((a,row,i)=>a+row[j]*s[i],0)+e[j]));
  const d=mod(dot(f.u,s)+delta*K+eta);
  const phase=mod(scale*d-dot(v,c));
  ck(phase===mod(scale*delta*K+scale*eta-dot(v,e)),"public affine phase");
  const decoded=dist(phase,scale*delta)<dist(phase,0)?1:0;
  ck(decoded===K,"perfect "+(scale===8?"FALSE attacker":"TRUE honest")+" recovery");
 };
 const honest=masks.map(mask=>mask===0?1:0);
 ck(T.H.every((r,i)=>dot(r,honest)===T.u[i]),"honest source certificate");
 for(let i=0;i<2048;i++){simulate(F,fake,8);simulate(T,honest,1)}
 ck(delta>2*(E0+E*masks.length),"genuine margin");
 ck(q>8*delta+16*(E0+E*masks.length),"scaled modulus margin");
 return {run:"R139-CUBIC-LOCAL-PSEUDOMOMENT-20261107",status:"REJECTED",assertions:checks,edges,stars,dimension:masks.length,clauses:16,scale:8,pseudo_l1:10,truth_satisfiers:truthCount,real_false_trials:2048,real_true_trials:2048,wrong_decodes:0,q,delta};
})()
~~~

Captured result:

~~~json
{"run":"R139-CUBIC-LOCAL-PSEUDOMOMENT-20261107","status":"REJECTED","assertions":8281,"edges":[[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]],"stars":[[0,1,2],[0,3,4],[1,3,5],[2,4,5]],"dimension":42,"clauses":16,"scale":8,"pseudo_l1":10,"truth_satisfiers":8,"real_false_trials":2048,"real_true_trials":2048,"wrong_decodes":0,"q":8191,"delta":128}
~~~
