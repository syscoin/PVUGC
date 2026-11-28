# R134: Boolean-residual quadratic source, rejected after locally normalized oracle attack

**Research-only negative record, not a secure generic ORIGINAL witness-KEM, not a user-facing update.** One bounded offline attempt on 2026-11-07. No web research or performance optimization.

## Starting point and exact construction

PR #1 remains the designated draft, branch research/pq-wkem-validation-20260918. R131 supplied a genuine source-dependent LWE challenge simulator for an ORIGINAL 3CNF but also a short signed FALSE opener; R132/R133 attempted nonlinear/local consistency with additional counterexamples. This trial changes the opening operation: random quadratic Boolean-residual masks are placed into the release evaluator, rather than merely requiring a supplied short representation.

For any proper 3CNF x with n Boolean variables and m clauses, construct the public integer matrix P_x and target t_x with B=n+2m selector pairs, N=2B coordinates, B pair normalization rows r_(b,0)+r_(b,1)=1 and m rows: sum of the three clause literal selectors minus one low-slack selector minus twice the high-slack selector equals one. Every satisfying ORIGINAL assignment w has an integer one-hot extension r(w) with P_x r(w)=t_x, ||r(w)||_1=B. Distinct valid witnesses need not share state.

Sample an odd prime q, delta=(q-1)/2, public A uniform in Z_q^(d×(B+m)), secret s uniform, independent small e, and REAL scalar-LWE g=A^T s+e mod q; equivalently allow uniform g as the exact decisional-LWE challenge hybrid. Independently sample bounded eta_i and eta_0 and uniform quadratic masks h_i in Z_q. Choose a frozen bit K. Let u=P_x^T g+eta, v=t_x^T g+eta_0+delta*K. Try to expose a public evaluable release E_x(r)=v-<r,u>+SUM_i h_i r_i(r_i-1) mod q, while concealing u,v,h behind the evaluator.

Every valid one-hot r(w) has zero quadratic residual, so E_x(r(w))=delta*K+eta_0-<r(w),eta> mod q; for |eta|<=h_err, h_err(B+1)<delta/2 makes nearest **circular** centre decoding deterministic for every valid ORIGINAL witness. A candidate source simulator given the genuine (A,g) LWE challenge can sample eta,h and compute E and deterministic context/auxiliary fields from actual public challenge bytes, without s, SourceOpen or a witness. This gives only the MODELLED source distribution, not independently implemented public secrecy. For a stronger test, grant a BLACK-BOX public E evaluator with hidden coefficients; real public code would expose at least as much. Uninstantiated secret-dependent checking keys, auxiliary inputs, related capsules and selective openings cannot restore a key already leaked by this reduced view. A QPT adversary can always execute the classical attack below.

## Exact attack with only locally admissible inputs

Let r0 consist of B one-hot pairs (1,0). Let rb flip the bth pair to (0,1) and leave all others unchanged. All B+1 inputs are locally Boolean and satisfy every pair-normalization equation, and hence all quadratic masks vanish on these queries. Query D0=E(r0) and Db=E(rb)-E(r0)=-(u_(b,1)-u_(b,0)) mod q. For ANY integer z with z_(b,0)+z_(b,1)=1, including negative entries, compute without asking E(z):

T(z)=D0+SUM_b z_(b,1)*Db=v-<z,u> mod q.

The R131 signed false representation is explicitly constructed without any ORIGINAL witness: take a public assignment a; each satisfied clause's slack encodes number-of-true-literals minus one; every violated clause instead uses low slack pair (2,-1) and high slack (1,0). Then P_x z=t_x with ||z||_1=B+2k for k violated clauses. Even on an unsatisfiable x, T(z)=delta*K+eta_0-<z,eta> mod q; bounded magnitude h_err(1+B+2k)<delta/2 permits deterministic K recovery. The adversary never queries E on the non-Boolean signed z. The attack works equally with real LWE or uniform challenge g and uses no source-opening oracle.

A concrete fixed FALSE x consists of all eight 3-literal clauses excluding each three-bit assignment: n=3,m=8,B=19,N=38. Public a=000 violates one clause, so ||z||_1=21. For q=65521, delta=32760 and error bound h_err=1, total error <=22; **20 one-hot-block oracle queries suffice**. A true example with four of these clauses has four distinct satisfying ORIGINAL witnesses and the SAME K opening for all four.

Stronger unrestricted Boolean probes recover v=E(0) and u_i=E(0)-E(e_i); even when h coefficients are hidden, unrestricted integer probes expose h_i=(E(-e_i)-E(0)-u_i)/2 mod q. Thus the specific quadratic correction repairs neither the FALSE-instance full-public view nor arbitrary recovery-to-ORIGINAL-witness extraction. This is a classical algebraic counterexample, not a QPT break of LWE.

## Attempted repair and handoff

Reject merely forbidding non-Boolean or non-onehot-block calls: the actual attack already uses onehot blocks. An ideal evaluator refusing all inputs that violate the FULL ORIGINAL 3CNF would eliminate this particular attack, but a reusable public classical implementation of an evaluator secretly holding K and releasing it only on satisfying ORIGINAL inputs is precisely the missing witness-conditioned release/obfuscation problem. Ordinary LWE IND-CPA, a plaintext NP checker or an inner-SNARG accepted bit do not independently provide it. This is not an independently instantiated repaired algorithm.

The full target requires classical-PPT genuine ORIGINAL-dependent source and QPT-LWE simulator together, every valid ORIGINAL witness recovering identical frozen native sigma, FALSE-instance complete-public hiding, and unauthorized arbitrary QPT recovery or native forgery implying an ACTUAL ORIGINAL witness or independently justified QPT hardness break without requiring a volunteered representation. Malicious N-of-N ceremony/abort, source qualification, CK/Aux/selective-opening/sibling-capsule correlations, calibrated QPT security and hypothetical Bitcoin native endpoint remain open. No optimization.

## Executed checker, source and captured result

The exact executable JavaScript checker below was run before publication. It builds actual P,t for both fixed FALSE and TRUE formulas, tests real toy LWE versus uniform challenge g, both K bits, 32 independent tapes per mode and key, every integer source equation, all valid-witness correctness and the fixed-FALSE locally normalized interpolation. Its toy d=4 parameters do not establish QPT hardness. Separately, a local CPython standard-library implementation passed **14,084** assertions over 64 tapes per mode and key, reproduced byte-identical output, and recorded a corrected circular modular-distance decoder; this independent Python artifact is LOCAL ONLY. All reported checker assertions concern finite algebra and functional behavior, not cryptographic strength.

```javascript
function r134Checker(){
 let checks=0, seed=1341107;
 const q=65521, delta=32760, mod=x=>((x%q)+q)%q, ck=(a,s)=>{checks++;if(!a)throw Error("R134 #"+checks+" "+s);};
 const rnd=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n;};
 const dot=(a,b)=>a.reduce((s,v,i)=>s+v*b[i],0);
 const dist=z=>Math.min(mod(z),mod(-z));
 const decode=z=>Number(dist(z-delta)<dist(z));
 const clauses=Array.from({length:8},(_,a)=>Array.from({length:3},(_,i)=>[i,((a>>i)&1)===0]));
 const sat=(a,cl)=>cl.every(c=>c.some(([i,p])=>((a>>i)&1)===Number(p)));
 function build(cl){
   const B=3+2*cl.length,N=2*B,P=[],t=[];
   const row=(ts,rhs)=>{let rr=Array(N).fill(0);for(const [i,v] of ts)rr[i]+=v;P.push(rr);t.push(rhs);};
   for(let b=0;b<B;b++)row([[2*b,1],[2*b+1,1]],1);
   cl.forEach((c,j)=>row([...c.map(([i,p])=>[2*i+Number(p),1]),[2*(3+2*j)+1,-1],[2*(3+2*j+1)+1,-2]],1));
   return {B,N,P,t,cl};
 }
 function rep(a,cl){
   let B=3+2*cl.length,r=Array(2*B).fill(0),bad=0;
   for(let i=0;i<3;i++)r[2*i+((a>>i)&1)]=1;
   cl.forEach((c,j)=>{
     const n=c.filter(([i,p])=>((a>>i)&1)===Number(p)).length;
     if(!n)bad++;
     const lo=n?((n-1)&1):-1,hi=n?((n-1)>>1):0;
     for(const [b,v] of [[3+2*j,lo],[3+2*j+1,hi]]){r[2*b]=1-v;r[2*b+1]=v;}
   });
   return {r,bad};
 }
 const F=build(clauses),T=build(clauses.slice(0,4));
 ck(F.B===19&&F.N===38&&F.P.length===27,"false dimensions");
 ck(T.B===11&&T.N===22,"true dimensions");
 ck(Array.from({length:8},(_,i)=>sat(i,F.cl)).every(x=>!x),"unsatisfiable");
 ck(Array.from({length:8},(_,i)=>sat(i,T.cl)).filter(Boolean).length===4,"four true witnesses");
 function test(S,mode,k){
   const {B,N,P,t,cl}=S,M=P.length,d=4;
   const A=Array.from({length:d},()=>Array.from({length:M},()=>rnd(q)));
   const s=Array.from({length:d},()=>rnd(q)),e=Array.from({length:M},()=>rnd(3)-1);
   const g=mode==="lwe"?Array.from({length:M},(_,j)=>mod(A.reduce((v,row,i)=>v+row[j]*s[i],e[j]))):Array.from({length:M},()=>rnd(q));
   const eta=Array.from({length:N},()=>rnd(3)-1),eta0=rnd(3)-1,h=Array.from({length:N},()=>rnd(q));
   const u=Array.from({length:N},(_,i)=>mod(P.reduce((v,row,j)=>v+row[i]*g[j],eta[i])));
   const v=mod(dot(t,g)+eta0+delta*k);
   const E=r=>mod(v-dot(r,u)+r.reduce((s,x,i)=>s+h[i]*x*(x-1),0));
   const zero=Array(N).fill(0),v0=E(zero),estimated=[];
   for(let i=0;i<N;i++){let ri=zero.slice();ri[i]=1;estimated.push(mod(v0-E(ri)));}
   ck(v0===v&&estimated.every((x,i)=>x===u[i]),"Boolean probes reveal affine source");
   for(let i=0;i<N;i++){let ri=zero.slice();ri[i]=-1;ck(mod((E(ri)-v0-estimated[i])*((q+1)/2))===h[i],"quadratic mask interpolation");}
   const baseline=Array.from({length:B},()=>[1,0]).flat(),base=E(baseline),diff=[];
   for(let i=0;i<B;i++){let ri=baseline.slice();ri[2*i]=0;ri[2*i+1]=1;diff.push(mod(E(ri)-base));}
   const fake=rep(0,cl);
   ck(P.every((row,i)=>dot(row,fake.r)===t[i]),"signed integer source satisfies P r=t");
   const interpolated=mod(base+diff.reduce((s,x,b)=>s+fake.r[2*b+1]*x,0));
   ck(interpolated===mod(v-dot(fake.r,u)),"locally-onehot oracle interpolation");
   if(S===F){ck(fake.bad===1,"FALSE assignment violation");ck(decode(interpolated)===k,"FALSE key recovered on every tested tape");}
   let valid=0;
   for(let a=0;a<8;a++){
     const {r,bad}=rep(a,cl);
     ck(P.every((row,i)=>dot(row,r)===t[i]),"source equation");
     ck((bad===0)===sat(a,cl),"ORIGINAL witness predicate");
     if(!bad){valid++;ck(E(r)===mod(delta*k+eta0-dot(r,eta)),"same frozen bit identity");ck(decode(E(r))===k,"all valid witnesses recover same bit");}
   }
   ck(valid===(S===F?0:4),"valid witness count");
 }
 const modes=[];
 for(const mode of ["lwe","uniform"])for(const key of [0,1]){
   for(let i=0;i<32;i++){test(F,mode,key);test(T,mode,key);}
   modes.push({mode,key,trials:32});
 }
 return {run:"R134-BOOLEAN-RESIDUAL-ORACLE",status:"REJECTED",assertions:checks,modes,local_normalized_queries:20,false_clauses:8,true_valid_witnesses:4,conclusion:"Public locally-onehot oracle interpolation lets classical attacker decrypt fixed FALSE, even with hidden quadratic coefficients and actual LWE sample or uniform challenge"};
}
console.log(r134Checker());
```

Captured run:
```json
{
  "run": "R134-BOOLEAN-RESIDUAL-ORACLE",
  "status": "REJECTED",
  "assertions": 14084,
  "modes": [
    {
      "mode": "lwe",
      "key": 0,
      "trials": 32
    },
    {
      "mode": "lwe",
      "key": 1,
      "trials": 32
    },
    {
      "mode": "uniform",
      "key": 0,
      "trials": 32
    },
    {
      "mode": "uniform",
      "key": 1,
      "trials": 32
    }
  ],
  "local_normalized_queries": 20,
  "false_clauses": 8,
  "true_valid_witnesses": 4,
  "conclusion": "Public locally-onehot oracle interpolation lets classical attacker decrypt fixed FALSE, even with hidden quadratic coefficients and actual LWE sample or uniform challenge"
}
```
