# Exact norm-rigid one-hot SOURCE: qualified representation, but false final-key release

**2026-10-27, bounded offline iteration; NO qualified positive practical witness-KEM advance.** The predecessor is anchored_fourier_null_20261027. The new polynomial SOURCE encoding provides a valid integer norm lemma, but its combination with the proposed public SOURCE-linear LWE release has an unconditional false-ORIGINAL final-key attack. This is not an independent QPT-LWE simulator, generic-NP WKEM, or recovery-to-ORIGINAL-witness proof.

## Explicit classical-PPT SOURCE encoding

Given any 3CNF F with v variables and c clauses (repeated literal occurrences allowed), form an anchor a; per variable two coordinates X_i^0,X_i^1; per clause three slack coordinates S_j^1,S_j^2,S_j^3; optionally d dummy two-coordinate groups. Set G=v+c+d, h=1+G and n=1+2v+3c+2d. Public integer M_F has G+c linear rows: sum of each group's coordinates equals a; for each clause, the sum of truthmaking variable coordinates over its three literal occurrences, plus S_j^1+2S_j^2+3S_j^3, equals 4a. The anchor selector e has e^T z=a.

For every valid ORIGINAL Boolean assignment W, set a=1, one variable/dummy coordinate per group, and slack S_j^(4-t_j)=1 where t_j in {1,2,3} is the number of true literal occurrences. This maps W in deterministic PPT into a binary h-weight f_F(W) with M_F f=0, e^T f=1. Conversely any binary anchor-one kernel opening obeys all 3SAT clauses (slack choice s in 1..3 requires t_j+s=4). Therefore accepted binary representation implies an ORIGINAL witness; witness states may differ.

## Integer norm-rigidity lemma

For any integer z with a=1 and every group summing to one, the exact identity

||z||_2^2 = h + sum_over_all_group_coordinates u(u-1)

holds. Every integer u has u(u-1) nonnegative and even, zero iff u is 0 or 1. Therefore squared norm >=h, and equality iff ALL groups are binary one-hot. If additionally M_F z=0, equality yields an ORIGINAL satisfying assignment. For false F, every integer anchor-one affine kernel z has squared norm >=h+2. When q exceeds any possible absolute row evaluation for ||z||^2<=h, modular zero implies integer zero in that ball. For the explicit parameters q=65537 and h=103, every row has coefficient L1 norm <=12, thus no modular wrap within the bounded-norm ball. This is valid representation-level SOURCE soundness, not final-key recovery extraction.

## Deterministic public false-source key recovery

Choose unsatisfiable ORIGINAL F=(x OR x OR x) AND ((NOT x) OR (NOT x) OR (NOT x)). Construct a public signed anchor-one vector using variable choice x=TRUE, positive-clause slack (1,0,0), and negative-clause slack (-1,1,1). This last slack sums to one and its weighted sum is -1+2+3=4, so ALL equations M_F z=0 hold over the INTEGERS even though no ORIGINAL W exists. Add d=99 dummy one-hot groups: h=103, n=207, rows=104, ||z||_1=||z||_2^2=105=h+2. This z is publicly computable without any witness, cryptographic secret, or setup randomness.

In the attempted release choose K the protected native signing seed with real pk(K), independent uniform 256-bit U,Z, public XOR shares D=U XOR Z and V=K XOR U. Encode one uniform Z injectively into 37 correlated radix-128 digits t_j. Publish p_j=M_F^T u_j+eps_j+512*t_j*e mod q, with q=65537, uniform u_j in F_q^104, and independent ternary error coordinates in {-1,0,1}. The false signed z computes z^T p_j=512*t_j+z^T eps_j mod q, and |z^T eps_j|<=105 for EVERY possible error and u. The cyclic distance between digit codepoints is at least min(512,65537-127*512)=512 and 2*105=210<512. Thus every t_j is recovered uniquely for every public capsule. Once the 37 digits are recovered, Z and then K=V XOR (D XOR Z) are recovered EXACTLY with no ORIGINAL witness. The actual checking key, context, auxiliary fields and independently keyed related capsules do not prevent this attack; related capsules may be empty. A native signature break or QPT attack is unnecessary.

A public instruction requiring ||z||^2<=h before release is not enforced: any adversary can ignore it and compute the linear product z^T p_j off chain. The repair therefore fails to connect arbitrary final-key recovery to an ORIGINAL witness or independent QPT hardness. This does not attack the independent unplanted uniform-M transverse-LWE reference. No credible false-source simulator can make this release secure, since a classical false-source adversary already obtains K with certainty.

## Checker, provenance and next equation

The exact JS checker below exhausts all 128 possible radix digits and 211 error sums (27,008 tests), validates the complete public signed kernel and integer group norm-rigidity, exhausts the small false SOURCE binary groups and checks two distinct valid ORIGINAL witness openings for a one-clause true formula. Separately, a full local Python checker computed the actual 37-column p_j distributions and reconstructed seven precommitted 256-bit K values across 259 digits; it passed 950 assertions in each of two byte-identical executions. These are exact identities and sample executions, NOT QPT hardness tests or native SLH implementation.

The missing equation is a polynomial-cost classical Setup_x, Release_x jointly secure for full public (ORIGINAL x, source data, capsule, native pk(K), claim/context/aux, related capsules), where every ORIGINAL W recovers the SAME K and arbitrary coherent-QPT unauthorized K/native forgery yields ORIGINAL W or an independently justified PQ break, without the attacker supplying z. The norm-rigid one-hot compiler does NOT supply that algorithm, nor standard-QPT-LWE simulation for structured M_F, false-source hiding, hard-true extraction, malicious setup/abort, selective openings or Bitcoin transaction-graph safety.

Provenance: syscoin/PVUGC draft/open/unmerged PR #1 on research/pq-wkem-validation-20260918, read starting head 3701508f433a9d919687da94eb414ee4f3f3fc06. Latest substantive top-level PR comment 6454556929. Exact prior file research/pq-wkem/anchored_fourier_null_20261027/RESEARCH.md blob e55dd86125ce5f9371ea52fa2a30882a931becc1. Actions: connected GitHub PR metadata, latest comments and exact file reads; offline Python and JS checks. No web/literature/external research, unrelated repo, subagent, native deployment or workflows. The following is the EXACT executed self-contained JS checker and captured output.

## Exact executed checker

```javascript
console.log(JSON.stringify((function checker(){
 const q=65537,g=512,m=128;let checks=0;
 const ok=(v,s)=>{if(!v)throw Error(s);checks++};
 const mod=x=>(x%q+q)%q,dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
 function build(C,d){
  const G=[[1,2]];let n=3;
  for(const c of C){G.push([n,n+1,n+2]);n+=3;}
  for(let j=0;j<d;j++){G.push([n,n+1]);n+=2;}
  const M=G.map(indices=>{let r=Array(n).fill(0);r[0]=-1;for(const i of indices)r[i]=1;return r;});
  for(let j=0;j<C.length;j++){let r=Array(n).fill(0);r[0]=-4;
   for(const [v,t] of C[j])r[G[v][t]]++;
   for(let k=0;k<3;k++)r[G[1+j][k]]=k+1;
   M.push(r);
  }return {G,M,n};
 }
 const F=[[[0,1],[0,1],[0,1]],[[0,0],[0,0],[0,0]]],S=build(F,99);
 let z=Array(S.n).fill(0);z[0]=z[S.G[0][1]]=z[S.G[1][0]]=1;
 for(let j=0;j<3;j++)z[S.G[2][j]]=[-1,1,1][j];
 for(let j=3;j<S.G.length;j++)z[S.G[j][0]]=1;
 ok(S.G.length===102&&S.n===207&&S.M.length===104,"dimensions");
 for(const row of S.M)ok(dot(row,z)===0,"exact false kernel");
 ok(z[0]===1&&dot(z,z)===105&&z.reduce((s,x)=>s+Math.abs(x),0)===105,"false ghost norms");
 const small=build(F,0);let binary=0;
 for(let bit=0;bit<2;bit++)for(let a=0;a<3;a++)for(let b=0;b<3;b++){
  let w=Array(small.n).fill(0);w[0]=w[small.G[0][bit]]=w[small.G[1][a]]=w[small.G[2][b]]=1;
  if(small.M.every(row=>dot(row,w)===0))binary++;
 }
 ok(binary===0,"unsatisfiable original");
 for(const len of [2,3]){
  function visit(a){if(a.length===len){if(a.reduce((s,x)=>s+x,0)!==1)return;
    let d=a.reduce((s,x)=>s+x*x-x,0);ok(d>=0&&d%2===0,"integer norm excess");
    ok((d===0)===a.every(x=>x===0||x===1),"onehot equality");return;}
   for(let v=-2;v<=3;v++)visit([...a,v]);}
  visit([]);
 }
 function nearest(y){let md=q+1,win=-1;for(let t=0;t<m;t++){
  const x=mod(y-g*t),dist=Math.min(x,q-x);if(dist<md){md=dist;win=t;}}
  return win;}
 for(let t=0;t<m;t++)for(let err=-105;err<=105;err++)
   ok(nearest(mod(g*t+err))===t,"all false release digit errors");
 const T=build([[[0,1],[0,0],[0,1]]],0);
 function witness(bit){let w=Array(T.n).fill(0);w[0]=w[T.G[0][bit]]=w[T.G[1][bit?1:2]]=1;return w;}
 let w0=witness(0),w1=witness(1);
 ok(w0.join()!=w1.join()&&T.M.every(r=>dot(r,w0)===0&&dot(r,w1)===0),"two true originals");
 ok(2*105<Math.min(g,q-127*g),"cyclic correction radius");
 return {status:"NO qualified positive WKEM advance",record:"onehot_norm_rigidity_20261027",false_source:{rows:S.M.length,columns:S.n,h:103,binary_witnesses:binary,public_signed_ghost_l1:105,public_signed_ghost_l2_squared:105},radix:128,q,g,exhaustive_digit_noise_pairs:128*211,true_original_witnesses:2,assertions:checks};
})(),null,2));
```

## Captured output

```json
{
  "status": "NO qualified positive WKEM advance",
  "record": "onehot_norm_rigidity_20261027",
  "false_source": {
    "rows": 104,
    "columns": 207,
    "h": 103,
    "binary_witnesses": 0,
    "public_signed_ghost_l1": 105,
    "public_signed_ghost_l2_squared": 105
  },
  "radix": 128,
  "q": 65537,
  "g": 512,
  "exhaustive_digit_noise_pairs": 27008,
  "true_original_witnesses": 2,
  "assertions": 27183
}
```
