# R136 — Module vanishing-polynomial ORIGINAL release (REJECTED; no foundational advance)

Research-only, one bounded offline iteration on 2026-11-07. No web/literature research, independent agent, optimization, or user-facing progress comment. The exact checker below was executed in the connected JavaScript runtime before writing. Independent LOCAL Python checker: 1444 assertions, twice byte-identical; not GitHub-published. Source status: draft/unmerged syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918, starting head fd540aba3a465a7ae2376eefae331bc3af6783de. Exact R135 predecessor blob c284fd47b491f53480d5e9418565d221a4d08090 and R134 excerpt blob 63efb6e6c47ffbe9648d895f9f5fbf92bebe7b06 were inspected. The latest substantive ordinary comment read was 6698876958.

## Explicit candidate and exact mathematical status

Given an ORIGINAL NP relation R_x on n-bit witnesses, choose field F_q with q > 2^n+1 and injective tags t_w=2+int(w). Let W_x={w:R_x(w)=1} and Z_x(T)=product_{w in W_x}(T-t_w), with Z_x=1 when FALSE. Choose module M=F_q^2, a random invertible PUBLIC linear frame U, random rho, frozen capability bit K, and Y_K=U*(K,rho). Publish a polynomial E_x(T)=Y_K+Z_x(T)Q(T) for random module-coefficient Q, together with Z_x, U, x and any deterministic public-checking/auxiliary hashes of displayed bytes. Opening with valid ORIGINAL w evaluates E_x(t_w) and applies the public decoder D_U=first coordinate of U^-1. Then for EVERY valid w, E_x(t_w)=Y_K, hence D_U=K exactly; witness states may differ. This proves only mathematical functionality of a non-PPT source enumerator, NOT a practical generic compiler.

For FALSE W_x=empty, Z_x=1; uniform Q constant makes the displayed (U,Z,E) distribution independent of K: sample-by-sample coupling changes Q_0 by Y_K-Y_K'. This statement does NOT extend to K-correlated native verification keys, CK/Aux secrets, context, related capsules or selective openings. No real LWE challenge simulator was instantiated.

## Public quotient attack and qualifications

For any monic public Z of positive degree and explicit module-coefficient public E, Euclidean division is legal using only public F_q-scalar operations in M. Therefore E modulo Z equals Y_K, and applying D_U reveals K WITHOUT evaluating any ORIGINAL witness. This is classical polynomial-time in explicit public coefficient length and works unchanged under public invertible linear frames. An independent public CK/Aux hash or related capsule cannot conceal information already recovered from the target E,Z. This is an unconditional algebraic failure of this candidate, NOT a QPT-LWE break.

Crucially, this is NOT an unconditional hard-TRUE extraction impossibility: if explicit deg Z is polynomial, Z itself describes all satisfying witness tags and finite-field factoring may reveal a witness. In addition, a Build computing all roots is generally exponential in n, violating classical PPT. For a compact succinct circuit of exponential formal degree, this note does not assert polynomial-time quotient division. Withholding Z might prevent the simple quotient attack, but then Build needs a private compact function vanishing at every valid ORIGINAL witness while enabling PUBLIC plaintext Eval from a compact capsule. Encrypting its coefficients under LWE only gives ciphertext-domain evaluation, not a witness-conditioned plaintext decryptor. That missing function was NOT constructed.

## Actual bounded checker and provenance

Two 3-CNF cases use n=3, q=257: a FALSE formula with all eight clauses excluding the eight assignments, and a TRUE four-clause subformula with four distinct witnesses. For each, 96 seeded trials sample frozen K, public invertible U, random Q and execute real polynomial operations. The TRUE case tests 384 successful all-witness common-capability evaluations and 96 public quotient recoveries. The FALSE case tests 96 exact K=0/K=1 two-world coefficient couplings. This is finite algebra and a countertest, not native signature, multi-capsule or QPT security testing.

~~~javascript
console.log(JSON.stringify((function runCheck(){
"use strict";
const q=257; let seed=1361107>>>0, checks=0, tested=0, openings=0, extracted=0, coupled=0;
const rand=(n)=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n;};
const mod=(x)=>((x%q)+q)%q;
const ck=(ok,msg)=>{checks++;if(!ok)throw Error("R136 check "+checks+" "+msg);};
function pmul(a,b){
 const z=Array.from({length:a.length+b.length-1},()=>[0,0]);
 for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++){
  for(let t=0;t<2;t++)z[i+j][t]=mod(z[i+j][t]+a[i][t]*b[j][t]);
 }
 return z;
}
function pscalar(a,b){
 const z=Array(a.length+b.length-1).fill(0);
 for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++)z[i+j]=mod(z[i+j]+a[i]*b[j]);
 return z;
}
function plus(a,b){
 return Array.from({length:Math.max(a.length,b.length)},(_,i)=>[
 mod((a[i]?.[0]??0)+(b[i]?.[0]??0)),mod((a[i]?.[1]??0)+(b[i]?.[1]??0))]);
}
function evalpoly(p,x){let v=[0,0];for(let i=p.length-1;i>=0;i--)v=[mod(v[0]*x+p[i][0]),mod(v[1]*x+p[i][1])];return v;}
function trim(p){while(p.length>1&&p[p.length-1].every(v=>v===0))p.pop();return p;}
function remMonic(p,z){
 let r=p.map(v=>v.slice());
 while(r.length>=z.length){
 const j=r.length-z.length, lead=r[r.length-1].slice();
 for(let k=0;k<z.length;k++)for(let t=0;t<2;t++)r[k+j][t]=mod(r[k+j][t]-lead[t]*z[k]);
 trim(r);
 }
 return r;
}
function fastpow(a,n){let z=1;while(n){if(n%2)z=mod(z*a);a=mod(a*a);n=Math.floor(n/2);}return z;}
const clauses=Array.from({length:8},(_,a)=>Array.from({length:3},(_,i)=>[i,1-((a>>i)&1)]));
function sat(w,cl){return cl.every(c=>c.some(([v,b])=>((w>>v)&1)===b));}
ck(Array.from({length:8},(_,i)=>sat(i,clauses)).every(v=>!v),"FALSE");
ck(Array.from({length:8},(_,i)=>sat(i,clauses.slice(0,4))).filter(Boolean).length===4,"TRUE four");
for(const [name,cl] of [["true",clauses.slice(0,4)],["false",clauses]]){
 const roots=Array.from({length:8},(_,i)=>i).filter(w=>sat(w,cl)).map(w=>w+2);
 let z=[1];for(const t of roots)z=pscalar(z,[mod(-t),1]);
 ck(z.length===roots.length+1&&z[z.length-1]===1,"monic root polynomial");
 for(let k=0;k<96;k++){
  const K=rand(2),rho=rand(q), u12=rand(q);let u21=rand(q),det=mod(1-u12*u21);
  while(det===0){u21=rand(q);det=mod(1-u12*u21);}
  const y=[mod(K+u12*rho),mod(u21*K+rho)];
  const dec=v=>mod((v[0]-u12*v[1])*fastpow(det,q-2));
  ck(dec(y)===K,"public invertible frame");
  const noise=Array.from({length:4},()=>[rand(q),rand(q)]);
  const E=plus([y],pmul(noise,z.map(v=>[v,v])));
  tested++;
  if(name==="true"){
   for(const w of roots){const o=evalpoly(E,w);ck(o[0]===y[0]&&o[1]===y[1],"same module value");ck(dec(o)===K,"same native bit");openings++;}
   const r=remMonic(E,z);
   ck(r.length===1&&r[0][0]===y[0]&&r[0][1]===y[1],"public remainder without witness");
   ck(dec(r[0])===K,"public decode");extracted++;
  }else{
   ck(z.length===1&&z[0]===1,"empty witness product");
   const opposite=1-K;
   const alt=[mod(opposite+u12*rho),mod(u21*opposite+rho)];
   const adjusted=noise.map(v=>v.slice());
   adjusted[0]=[mod(noise[0][0]+y[0]-alt[0]),mod(noise[0][1]+y[1]-alt[1])];
   const E2=plus([alt],pmul(adjusted,z.map(v=>[v,v])));
   ck(JSON.stringify(E)===JSON.stringify(E2),"FALSE exact joint public coefficients coupling");coupled++;
  }
 }
}
return {run:"R136-POLYNOMIAL-MODULE-VANISHING",status:"REJECTED",q,assertions:checks,trials:tested,true_openings:openings,public_remainder_recoveries:extracted,false_key_couplings:coupled,qualifier:"Classical polynomial-time only in explicit coefficient length; setup enumerates witnesses and is not generic PPT."};
})(),null,2));
~~~

Captured checker output (executed independently of file creation):

~~~json
{
  "run": "R136-POLYNOMIAL-MODULE-VANISHING",
  "status": "REJECTED",
  "q": 257,
  "assertions": 1348,
  "trials": 192,
  "true_openings": 384,
  "public_remainder_recoveries": 96,
  "false_key_couplings": 96,
  "qualifier": "Classical polynomial-time only in explicit coefficient length; setup enumerates witnesses and is not generic PPT."
}
~~~

## Exact next obligation

Reject explicit public-module quotient masking as a non-subtractable source. Construct a classical-PPT joint ORIGINAL-dependent Build and LWE challenge simulator, with publicly evaluable off-chain plaintext release to the SAME precommitted native signature for every valid ORIGINAL witness, and prove full-public FALSE and arbitrary hard-TRUE QPT security against checking key/auxiliary/related-capsule/selective-opening correlations. Arbitrary accepted native forgery or early K recovery must imply an ACTUAL ORIGINAL witness or an independently justified QPT break, without asking an adversary to provide a representation. No generic solution or accepted component follows from R136. Keep automation enabled; no notification warranted.