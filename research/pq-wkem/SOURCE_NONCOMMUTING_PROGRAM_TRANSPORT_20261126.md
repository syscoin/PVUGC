# Noncommuting branching-program transport trial — 2026-11-26 UTC

Status: rejected construction/repair iteration, not a qualifying original-source release advance. No ordinary PR comment.

Continuity: actual syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, starting head 0ee3e145c44c1756a72f79e57c944eb1cb31e4ef. Read PR metadata and latest four substantive discussion entries through R225; read exact SOURCE_GLOBAL_TRANSPORTER_REFINEMENT_20261126.md (blob 428cc526a9289967e7399351723f4311ae21be12), SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md and SOURCE_LATE_BOUND_MERKLE_ROOT_GARBLING_20261126.md at that head. Re-read metadata before write and confirmed this new path returned NOT_FOUND/404. No new Core claims.

## 1. Candidate selection and actual missing operation

Missing: offline classical PPT Build must serialize a cryptographic map from ANY future qualifying ORIGINAL certificate to exactly the same frozen native cancellation contribution S, with arbitrary full-public QPT recovery implying actual original certificate or independently justified hash/native break. Keep all three source OR branches and authentic/relevant claim bindings, depth and work policies. Neither new source authority nor altered evidence. Treat R(x,w) as the bounded complete original verifier; it is not implemented in this note.

The preceding global-transporter candidate used monotone singleton matching and failed by greedy closure. The explicit mathematical change here is a nonmonotone product of NONCOMMUTING permutations, applied to a complete sequential state in each independently randomized lane, rather than resolving names one by one or combining independently supplied output wire labels. Global witness consistency would ideally come from the formula program's product, which yields one fixed accepting permutation for every satisfying witness regardless of its contents. No discrete-log, group-action, graph-isomorphism or lattice hardness is assumed. The permutations on five symbols are public, explicit combinatorial maps; only the hash of the complete hidden endpoint tuple masks S. Investigate a new exact public normalization before relying on reversible-frame or local-label security; do not scale masks/fixtures.

## 2. Actual serialized candidate

Given a bounded fan-in-two Boolean verification circuit for R, extend the opening certificate by its complete deterministic gate trace. Construct a Boolean formula F that checks each gate relation, public constants, and final output equal to one. Each local constraint has constant size; balance the conjunction, giving O(log circuit-size) depth and polynomial size. A satisfying assignment to F decodes to the original w, and every qualifying w efficiently yields a satisfying assignment by forward evaluation. This does not relax source authentication or introduce a distinct hard witness. Actual source circuit and bounds remain outside this trial.

Compile F to a permutation program over S5 with public input indices j_i and pairs M_i,0, M_i,1; row i applies M_i,b where b is the assignment bit at j_i. Use right-to-left composition, so the product on input a is W(a)=M_L,a[j_L] ... M_1,a[j_1]. The compiler targets a specified 5-cycle g: output W(a)=g if F(a)=1, identity otherwise. For completeness of the abstract compiler, a literal is a single conditional row with branches identity and g (swapped for negation). For AND, recursively target two 5-cycles p,q whose commutator q^-1 p^-1 q p is a 5-cycle; conjugate both by a fixed relabeling so that commutator is g. Concatenate the two child programs, their inverses (reverse row order and invert each row map), in that order. If either child evaluates to identity the commutator is identity; if both true it is g. A NOT uses the inverse child product followed by a fixed multiplication by g, and OR is implemented via De Morgan. Constants are constant rows. A pair p,q with the requisite property is provided by the checker below. The length grows at most exponentially in depth, hence polynomial for the balanced trace formula. This is a public deterministic compiler, not a claimed secure encoding.

Choose m polynomially many lanes. Independently per lane h choose P_h,0,...,P_h,L uniformly from S5. Choose a public point z0 in {0,...,4}, e.g. zero. Publish y_h,0=P_h,0(z0), and both explicit row maps

    A_h,i,b = P_h,i M_i,b P_h,i-1^-1.

Compute t_h=P_h,L(g(z0)). Set t=(t_1,...,t_m). Publish D=S XOR H("native-pad",ctx,enc(t)) for one hash-output block; extend with independent domain-separated counter blocks for arbitrary native contribution length. The encoding includes tuple length and lane ordering. Include public statement, program indices, all rows, native checking information and context. Build is classical PPT, knows t but not a source witness; erase masks. Take m >= lambda for at least lambda bits of raw tuple entropy before the public rows (this is not a conditional-entropy or security claim).

Open: validate original w, construct its trace assignment a, and start with each y_h,0. Apply the serialized A_h,i,a[j_i] successively. Telescoping gives P_h,L(W(a)(z0)). For every qualifying w, W(a)=g, so the same t is obtained and exactly S is recovered. Thus correctness is real for this abstract bounded compiler, no hash coincidence or common witness preimage required. The public source check in Open is not granted as a release barrier; adversary can use A maps directly.

## 3. Exact normalization and public attack (not an affine argument)

For each lane suppress h. Set U_0=V_0=identity and

    U_i = M_i,0 U_i-1,
    V_i = A_i,0 V_i-1,
    D_i = U_i^-1 M_i,1 U_i-1,
    E_i = V_i^-1 A_i,1 V_i-1.

All quantities are public for the deterministic compiler. Telescoping gives V_i=P_i U_i P_0^-1. Substitution gives E_i=P_0 D_i P_0^-1. This is a single simultaneous conjugation of ALL relative rows, irrespective of how independent the per-layer masks are. For a consistent assignment a, let b_i=a[j_i]. Then

    U_L^-1 W(a) = D_L^b_L ... D_1^b_1.

Proof: normalize each partial product by the corresponding U_i; the normalized zero transition is identity, the one transition is D_i. No commutativity is used. Therefore if any qualifying original witness exists, the PUBLIC element d*=U_L^-1 g lies in the subgroup generated by the D_i.

Public Recover: find ANY word over generators D_i reaching d* by breadth-first search on the 120 explicitly enumerable permutations. Forward edges alone suffice because a finite permutation's inverse is a positive power. This costs O(120 L) constant-sized permutation operations and yields a word of length <=119. This is NOT a source witness or a sequence required to respect input indices, order, or even use each instruction only once. For each lane apply the corresponding word of E_h,i to y_h,0 and then apply V_h,L. The result is

    V_h,L P_h,0 d*(z0) = P_h,L g(z0) = t_h.

One word works simultaneously for every independently masked lane. For publicly known different compilers per lane compute the corresponding public word independently. Recover hashes the full t and recovers exact S. It need not guess m endpoint symbols, search hash preimages, solve a discrete log, use a native verifier or know a single source witness. A classical adversary is already sufficient. On every complete true instance of this compiler the attack succeeds pointwise for all masks; on hard-TRUE distributions where actual certificate recovery remains hard, a security claim would require an additional genuine source finder, not extraction of this subgroup word. The attacker has no source-specific input beyond the public capsule. Related capsules, auxiliary data and native checking keys can simply be ignored.

FALSE is also possible whenever d* happens to lie in the subgroup despite absence of consistent witnesses. Example F=x AND NOT x. Let p=(0 1 2 3 4) and q=(0 1 3 4 2) as in the checker; use array representations below. Rows implement p conditional on x=1, q conditional on x=0, then their inverses. Both consistent assignments yield identity. The independent row choices [1,0,1,0] give g=q^-1 p^-1 q p; the public subgroup attack does not even need that full word. The checker constructs the pair, verifies the exact normal-form equation and recovers all eight independently framed example endpoints. This is a synthetic formula counterexample, not actual BTC/SYS source evidence. No assertion about the false-instance subgroup membership of an unimplemented source compiler is needed for the hard-TRUE rejection.

## 4. Repair attempted: hide the compiler, not just the masks

First try independent secret random choices of child-target cycles and their conjugations at every AND, with the same public formula-to-instruction occurrence map (necessary for this particular straightforward serialization). This might make M_i unknown and obstruct the above construction of d*. It does not repair the compiler. For the formula expanded as a tree, replace each syntactic leaf occurrence of an assignment variable by a separate Boolean variable. Every duplicate of THAT leaf occurrence introduced by commutator construction or inversion retains that same new occurrence ID. By induction on the compiler, it computes the relaxed occurrence formula for all these independent values, regardless of the secret child-target cycles, including through inverse blocks. If the relaxed formula has a satisfying assignment, the public evaluator can apply the corresponding row choices using the occurrence map. For x AND NOT x choose the positive occurrence true and the negative occurrence false. More generally, nonconstant trace constraints can be individually satisfied when occurrences are independent; a global claim for any particular source circuit needs its actual formula, and is not asserted here. Hidden child-target permutations alone cannot prevent this attack. No hash break or group assumption.

Second attempt: conceal even the occurrence map by a secret randomized compiler whose public interface exposes only j_i and the two masked row maps. Honest Open can still use the original assignment. The above two attacks no longer automatically cover a completely unspecified compiler with hidden occurrences and hidden M; do NOT claim they do. But independent per-layer masking has an exact public normal form even for secret M. Conditional on M and P_0, the V_i for i>=1 are independent uniform permutations since the P_i are independent. The full row data is in bijection with (V_i,E_i):

    A_i,0 = V_i V_i-1^-1,
    A_i,1 = V_i E_i V_i-1^-1,
    E_i = P_0 D_i P_0^-1.

The published start is P_0(z0); the target is V_L P_0 d*(z0). Thus the random frames themselves hide only by a single conjugation on a 120-element set; the real remaining burden is a serialized randomized compiler whose complete normalized row distribution (with public indices, starts, native checks, context and multiple lanes/capsules) hides the normalized accepting endpoint, while public source assignments still evaluate it. No such compiler or simulator was constructed. Random padding or reordering without a proof of that joint distribution is not a repair; the five-symbol finite group supplies no independent security foundation. The actual required equation is target-sensitive full-public simulation or original-certificate extraction for this normalized compiler. Do not retry merely with more lanes, larger finite permutations, another reversible mask, or changing the hash of t.

## 5. Scope and next work

Reject the deterministic noncommuting-program transport candidate before implementing a real source verifier. The nonmonotone, globally composed path did achieve a pointwise same-value output for all source assignments, but the exact normalization converts target recovery to small public subgroup search without any source evidence. The attempted secret compiler would need new source-dependent semantics hiding its accepting endpoint, not larger fixtures. This is not a theorem against arbitrary noncommutative encodings or hash-only source-specific computational release.

No original BTC/SYS verifier instantiation, actual native signature, independently QPT-secure Build/Open, malicious setup/capsule acceptance, source-correlated auxiliary or related-capsule proof. No new Core source inspection, deployment claim, external literature, other repository action or delegated agents. R316 maturity and R225 endpoint scope unchanged. Strict notification gate not met.

## 6. Exact bounded checker and captured output

Executed in the JS tool isolate, first standalone and again for this preservation record. The eight deterministic mask fixtures are NOT random samples or security parameters. The algebraic attack, not their number, establishes the stated candidate failure. The standalone reproducible code is the function below followed by `console.log(JSON.stringify(check()))` in a JS environment.

```javascript
function check(){
  const I=[0,1,2,3,4], comp=(p,q)=>q.map(i=>p[i]), inv=p=>I.map(i=>p.indexOf(i)), key=p=>p.join(""), eq=(p,q)=>key(p)===key(q);
  const cycle=a=>{const p=I.slice();a.forEach((v,i)=>p[v]=a[(i+1)%a.length]);return p;};
  const perm=a=>a.length===0?[[]]:a.flatMap((v,i)=>perm(a.filter((_,j)=>i!==j)).map(p=>[v,...p]));
  const all=perm(I), alpha=cycle(I), comm=(p,q)=>comp(inv(q),comp(inv(p),comp(q,p)));
  const five=p=>{let v=0;const s=new Set();do{s.add(v);v=p[v];}while(!s.has(v));return s.size===5;};
  const beta=all.find(q=>five(q)&&five(comm(alpha,q))), gamma=comm(alpha,beta);
  const M=[[I,alpha],[beta,I],[I,inv(alpha)],[inv(beta),I]];
  const product=(rows,bits)=>rows.reduce((a,r,i)=>comp(r[bits[i]],a),I);
  if(!eq(product(M,[0,0,0,0]),I)||!eq(product(M,[1,1,1,1]),I)||!eq(product(M,[1,0,1,0]),gamma))throw Error("formula");
  const prefix=rows=>rows.reduce((p,r)=>[...p,comp(r[0],p[p.length-1])],[I]);
  const U=prefix(M), D=M.map((r,i)=>comp(inv(U[i+1]),comp(r[1],U[i]))), target=comp(inv(U[4]),gamma);
  const seen=new Map([[key(I),[]]]),queue=[I];
  for(let j=0;j<queue.length&&!seen.has(key(target));j++){
    const p=queue[j];
    D.forEach((d,i)=>{const q=comp(d,p);if(!seen.has(key(q))){seen.set(key(q),[...seen.get(key(p)),i]);queue.push(q);}});
  }
  const word=seen.get(key(target));if(!word)throw Error("subgroup");
  const targets=[],recovered=[];
  for(let lane=0;lane<8;lane++){
    const P=Array.from({length:5},(_,i)=>all[(17*lane+31*i+7)%all.length]);
    const A=M.map((r,i)=>r.map(m=>comp(P[i+1],comp(m,inv(P[i])))));
    const V=prefix(A), E=A.map((r,i)=>comp(inv(V[i+1]),comp(r[1],V[i])));
    E.forEach((e,i)=>{if(!eq(e,comp(P[0],comp(D[i],inv(P[0])))))throw Error("normalization");});
    const y0=P[0][0], y=word.reduce((v,i)=>E[i][v],y0), got=V[4][y], want=P[4][gamma[0]];
    if(got!==want)throw Error("attack");
    targets.push(want);recovered.push(got);
  }
  return {alpha,beta,gamma,subgroupWordZeroBased:word,consistentAssignmentsAccept:0,independentOccurrenceBits:[1,0,1,0],targets,recovered,lanes:8,maskSelection:"deterministic validation only"};
}
console.log(JSON.stringify(check()));
```

Captured returned object (both runs):

```json
{
  "alpha": [
    1,
    2,
    3,
    4,
    0
  ],
  "beta": [
    1,
    3,
    0,
    4,
    2
  ],
  "gamma": [
    4,
    3,
    1,
    0,
    2
  ],
  "subgroupWordZeroBased": [
    0,
    2
  ],
  "consistentAssignmentsAccept": 0,
  "independentOccurrenceBits": [
    1,
    0,
    1,
    0
  ],
  "targets": [
    1,
    3,
    0,
    4,
    2,
    3,
    0,
    3
  ],
  "recovered": [
    1,
    3,
    0,
    4,
    2,
    3,
    0,
    3
  ],
  "lanes": 8,
  "maskSelection": "deterministic validation only"
}
```
