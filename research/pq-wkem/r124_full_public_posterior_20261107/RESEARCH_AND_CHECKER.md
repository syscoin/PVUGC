# R124 — Full-public posterior test for the ORIGINAL-dependent noisy projective source (UNRESOLVED)

Run R124-FULL-PUBLIC-POSTERIOR-20261107. Repository syscoin/PVUGC#1, existing branch research/pq-wkem-validation-20260918, observed starting SHA 9a2112b2cbd283b108c4a4af77bb8dec14a968e9. Prior R123 research blob d24a8c5526ba0825a437e55a1429fc91f9398d68. Latest ordinary PR substantive comment 6698876958. Offline-only mathematics, no external literature research. **No positive secure generic NP witness-KEM advance; no user-facing progress comment.**

## Attempted constructive repair
R121/R122A's independent large-gap source let a short but invalid integer affine representation recover the hidden pad. R123's correlated-block noise instead leaked the pad deterministically through residues. The next candidate tested an **independent narrow-center XOR release**: for each final pad bit K sample r independently released source bits B_i with XOR_i B_i=K. All ORIGINAL valid witnesses would reconstruct each B_i and the same final frozen native signature; unauthorized affine projections should have nonzero decoding error for each bit, causing parity uncertainty. This **would not** be a valid construction until complete-public overlap, simultaneous honest correctness and extraction are proved jointly.

## Exact entire-public source calculation
For one fixed FALSE 3CNF block (X∨X∨X) AND (¬X∨¬X∨¬X), write:
A = [[1,1,0,0,0,0,0,0],[0,0,1,1,1,0,0,0],[0,0,0,0,0,1,1,1],[0,3,0,1,2,0,0,0],[3,0,0,0,0,0,1,2]],
b = [1,1,1,3,3],
z = [0,1,1,0,0,0,-1,2],
N = [[0,0,3,-6,3,0,0,0],[-1,1,3,-3,0,-3,3,0],[-2,2,6,-6,0,-3,0,3]].
Then A z=b, N A^T=0 and N spans the left-nullspace of A^T modulo primes q>3. For t disjoint copies, honest setup samples alpha_j uniformly conditioned on sum_j(alpha_j·b)=h_B mod q, and independent e_j uniform on {-1,0,1}^8. It publishes every complete p_j=A^T alpha_j+e_j modulo q, not just the scalar z·p_j.

Set s_j=N p_j mod q, V=sum_j z·p_j mod q, and F_s(c)=number of e∈{-1,0,1}^8 with N e=s and z·e=c modulo q. Since A^T is injective, every compatible error tuple uniquely specifies alpha and satisfies the hyperplane condition exactly when sum_j z·e_j=V-h_B mod q. Therefore the **exact full-public** likelihood is

 Pr[(p_1,...,p_t)|B] = q^{-(5t-1)} 3^{-8t} (F_{s_1} * ... * F_{s_t})(V-h_B mod q).

The sufficient statistic is (s_1,...,s_t,V). All complete p vectors in one fiber have equal probability under either B. This holds information-theoretically for the stated output distribution even against coherent QPT distinguishers. It does **not** cover arbitrary CK/J/Aux, native verification key, context, related capsules or selectively opened secret coins unless they are independently simulated; none are assumed away.

Exhaustive local error enumeration gives 945 syndrome classes, 6463/6561 local error tapes with at least two conditional c values, and exact
 E_s Var[z·e | N e=s] = 13389413/15155910 ~=0.88344500594.
The original forged projection has unconditional noise variance 14/3, but its noise **after observing the full public syndrome** has residual variance 0.88345, compared with variance 2 for a three-coordinate one-hot honest witness. Thus a naive attempt to choose q from the larger 14/3 forged-noise variance, then amplify via XOR, uses the wrong channel. The complete public view substantially denoises the affine attack. This is not by itself a quantified break for every q/t/r, but it defeats the unqualified purported noise-gap argument.

## Exact conditional parity identity and missing security condition
If each bit-channel has exact entire-public laws P_0 and P_1, if channels are conditionally independent, and if **all additional public checking keys, auxiliary inputs, context, sibling capsules and quantum advice admit the required joint simulation**, the exact total-variation distance between r independently exposed channels constrained to XOR K=0 versus K=1 is TV(P_0,P_1)^r. This standard algebraic identity is not a new encryption assumption and does not instantiate the prerequisite source hiding. For this candidate the remaining quantitative obligation is to prove, for EVERY FALSE ORIGINAL instance after an explicit polynomial compiler,

 E_{s_1,...,s_t} TV( F_{s_1}*...*F_{s_t}, shift_{h_1-h_0}(F_{s_1}*...*F_{s_t}) ) <= 1-delta(lambda),

with r*delta(lambda)=omega(log lambda) **and** simultaneous negligible failure for every valid ORIGINAL witness over all r source openings. A proof only about the unconditioned scalar projection does not suffice. A separate arbitrary unauthorized QPT native signature recovery/forgery -> ORIGINAL witness or independent QPT break is still required. No SourceOpen oracle, canonical witness, supplied-representation extraction or new WE/iO assumption may be substituted.

## Assessment and handoff
**No positive foundational advance:** this is a proven sufficient-statistic/conditional-variance diagnostic for one fixed FALSE family, not a secure generic compiler, not arbitrary hard-TRUE extraction, not a QPT hardness estimate, not malicious N-of-N ceremony or deployable native Bitcoin PQ. The parity-repair proposal is unfinished and cannot be promoted. Before further experiments, solve the missing complete-public overlap plus honest correctness conflict with an actually instantiated ORIGINAL-dependent source, or replace the source. Do not optimize sizes. The code and captured result follow exactly; assertions verify finite algebra, not QPT security.

## Exact executed JS checker
~~~javascript
function checkR124(){
  const A=[[1,1,0,0,0,0,0,0],[0,0,1,1,1,0,0,0],[0,0,0,0,0,1,1,1],[0,3,0,1,2,0,0,0],[3,0,0,0,0,0,1,2]];
  const b=[1,1,1,3,3], z=[0,1,1,0,0,0,-1,2];
  const N=[[0,0,3,-6,3,0,0,0],[-1,1,3,-3,0,-3,3,0],[-2,2,6,-6,0,-3,0,3]];
  let assertions=0;
  const ck=(v,m)=>{assertions++;if(!v)throw Error(m)};
  const dot=(a,b)=>a.reduce((s,v,j)=>s+v*b[j],0);
  const mv=(M,v)=>M.map(row=>dot(row,v));
  ck(JSON.stringify(mv(A,z))===JSON.stringify(b),"A z=b");
  for(const row of N)for(const ar of A)ck(dot(row,ar)===0,"N A^T=0");
  const buckets=new Map();
  for(let t=0;t<6561;t++){
    let x=t;const e=Array.from({length:8},()=>{let y=x%3-1;x=Math.floor(x/3);return y});
    const syndrome=mv(N,e).join(","),c=dot(e,z);
    if(!buckets.has(syndrome))buckets.set(syndrome,new Map());
    const counts=buckets.get(syndrome);counts.set(c,(counts.get(c)||0)+1);
  }
  ck(buckets.size===945,"945 syndrome classes");
  let amb=0;
  const gcd=(a,b)=>{while(b){let t=a%b;a=b;b=t}return a};
  const add=([a,b],[c,d])=>{let n=a*d+c*b,den=b*d,g=gcd(n,den);return[n/g,den/g]};
  let vcond=[0n,1n];
  for(const counts of buckets.values()){
    let n=0n,sum=0n,sum2=0n;
    for(const[c,k]of counts){const bn=BigInt(k),bc=BigInt(c);n+=bn;sum+=bc*bn;sum2+=bc*bc*bn}
    if(counts.size>1)amb+=Number(n);
    vcond=add(vcond,[n*sum2-sum*sum,BigInt(6561)*n]);
  }
  ck(amb===6463,"ambiguous tapes");
  ck(vcond[0]===13389413n&&vcond[1]===15155910n,"exact residual variance");
  const q=101,At=(alpha)=>Array.from({length:8},(_,j)=>A.reduce((s,row,k)=>s+row[j]*alpha[k],0));
  const mod=x=>(x%q+q)%q;
  const alpha=[13,11,17,23,29],delta=[3,-3,0,0,0],e=[0,1,-1,1,0,-1,1,0];
  const p=At(alpha).map((v,j)=>mod(v+e[j]));
  const p2=At(alpha.map((v,j)=>mod(v+delta[j]))).map((v,j)=>mod(v+e[j]));
  ck(dot(delta,b)===0,"hyperplane-preserving translation");
  ck(JSON.stringify(mv(N,p).map(mod))===JSON.stringify(mv(N,p2).map(mod)),"syndrome invariance mod q");
  ck(mod(dot(z,p))===mod(dot(z,p2)),"V invariance");
  const views=[];
  for(let ix=0;ix<8;ix++){
    const aa=Array.from({length:5},(_,k)=>mod(3+17*k+ix*7));
    const ee=Array.from({length:8},(_,j)=>(ix+2*j)%3-1);
    const pp=At(aa).map((v,j)=>mod(v+ee[j]));
    const ss=mv(N,pp).map(mod).join(","),v=mod(dot(z,pp));
    for(const bit of [0,1]){
      const h=bit*50;let direct=0,stats=0;
      for(let t=0;t<6561;t++){
        let x=t;const e0=Array.from({length:8},()=>{let y=x%3-1;x=Math.floor(x/3);return y});
        const rr=pp.map((v,j)=>mod(v-e0[j]));
        if(mv(N,rr).every(y=>mod(y)===0)&&mod(dot(z,rr))===h)direct++;
        if(mv(N,e0).map(mod).join(",")===ss&&mod(v-dot(z,e0)-h)===0)stats++;
      }
      ck(direct===stats,"full public likelihood identity");
      views.push({ix,bit,count:direct});
    }
  }
  return {run:"R124-FULL-PUBLIC-POSTERIOR-20261107",assertions,syndrome_classes:buckets.size,noise_vectors:6561,ambiguous_error_tapes:amb,conditional_variance:vcond.map(String).join("/"),conditional_variance_decimal:Number(vcond[0])/Number(vcond[1]),honest_onehot_variance:2,full_public_likelihood_fixtures:views.length,status:"RESEARCH DIAGNOSTIC ONLY; no secure generic ORIGINAL-dependent source or arbitrary QPT extraction"};
}
console.log(JSON.stringify(checkR124(),null,2));
~~~

## Captured output
~~~json
{
  "run": "R124-FULL-PUBLIC-POSTERIOR-20261107",
  "assertions": 38,
  "syndrome_classes": 945,
  "noise_vectors": 6561,
  "ambiguous_error_tapes": 6463,
  "conditional_variance": "13389413/15155910",
  "conditional_variance_decimal": 0.8834450059415766,
  "honest_onehot_variance": 2,
  "full_public_likelihood_fixtures": 16,
  "status": "RESEARCH DIAGNOSTIC ONLY; no secure generic ORIGINAL-dependent source or arbitrary QPT extraction"
}
~~~
