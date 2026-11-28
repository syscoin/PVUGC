# Nonseparable row operators with staged hidden state — 2026-11-25

Status: explicit repair candidate rejected on its factorable-state serialization. No qualifying original-source WKEM or ordinary PR comment.

## Continuity and selection before implementation

Actual syscoin/PVUGC PR #1 open/draft/unmerged, head repository syscoin/PVUGC, branch research/pq-wkem-validation-20260918, start and prewrite head 97d67daa680c841203529dae526c958656743838. Read actual metadata, recent substantive discussion through R225, head commit changed-file metadata, exact-head SOURCE_EXACT_AMPLITUDE_DECOY_CAPSULE_20261125.md (blob 77466404d7011a2bbeeebacf5016c7063ff372a7), SOURCE_ENTANGLED_PROJECTOR_CAPSULE_20261125.md, SOURCE_STREAMING_FINGERPRINT_CAPSULE_20261125.md, SOURCE_SCOPED_TELESCOPING_KEYS_20261125.md, SOURCE_PUBLIC_FSS_TERMINAL_REPAIR_20261125.md and SOURCE_FULL_INPUT_PREPROCESSING_20261125.md. New path absent (404). No external literature/web, full PR diff, Core source fact, production operation or independent agents.

Missing operation: serialized classical-PPT Build from the entire bound original statement x and frozen native cancellation S, with Open using any qualifying original witness and returning exactly S; jointly simulatable arbitrary-QPT public view. Mathematical change from immediate predecessor: instead of a product of local transition operators with an exposed separable operator tensor, each complete allowed gate row gets a freshly sampled dense invertible operator, constrained on just one hidden input product vector and one output product vector. It can act arbitrarily on the complement. Thus a row's operator is generally not Kronecker rank one; the previous factor-the-row-matrix attack is not applicable. Refresh local state vectors at every occurrence, including repeated checks; there are no exposed per-wire transition keys or static projectors, and no affine private-coefficient evaluator. The exact amplitude of the common terminal state is still included in the KDF. The point is to test whether nonseparable row maps and changing labels suffice to gate the entire source predicate, not vary the field size or entangling depth.

## Actual candidate and attempted simulator

Let R_x(w) be the complete unchanged bounded three-ground ORIGINAL relation, with all source, claim, replay, maturity, window, baseline and native endpoint fields in x. Compile it to bounded-arity local Boolean gate/check constraints and a chronological stream of allowed local rows, including output=1 and canonical encodings. A consistent allowed stream projects to a qualifying original witness; every qualifying witness gives such a stream. This is a proposed compiler, not actual Core verification. Use a constant dimension d>=2 over a prime field F_p, with polynomial-bit p. Use distinct variables within each constraint, absorbing repeated variables into its local truth table.

For each wire i occurring k_i times, sample a nonzero initial vector u_i, terminal vector v_i, and independent nonzero vectors e_(i,j,b) for each interior occurrence frontier 1<=j<k_i and bit b. Choose distinct projective lines for the two bits at each frontier. Allow random independent nonzero amplitude on every vector. At occurrence j the local input vector is u_i for j=1, otherwise e_(i,j-1,b). The local output vector is v_i for j=k_i, otherwise e_(i,j,b). For a complete allowed row a of gate g, form X_g,a and Y_g,a as the tensor products of these respective input and output vectors for the row's bits. Independently sample two full bases P,Q of F_p^(d^arity) with first columns X_g,a and Y_g,a; publish the complete dense matrix A_g,a=Q P^-1. Build can sample by independent extension to a basis, with polynomial expected time and negligible abort under a polynomial trial cap. Its size is constant per row in d and arity, independent of the number of other wires. No separate local matrix factors are published. For each row A_g,a X_g,a=Y_g,a exactly. Wrong inputs need not produce product outputs at all.

Publish the exact initial product tensor U, represented canonically by normalized per-wire factors plus its overall scalar, the ordered matrices, and D=enc(S) xor H_expand(domain,x,capsule_id,CanExact(V)), where V is the exact product of all v_i. In this trial CanExact serializes normalized factors and the nonzero overall scalar, so it distinguishes scalar multiples. The serialized classical Open evaluates the actual verifier on w to select the consistent allowed rows and applies each dense row matrix to the indicated local factors, refactors the resulting product exactly, and updates the overall scalar. It ends at V for every qualifying witness and returns the SAME S. A valid row acts on a constant-size product tensor; this evaluation, setup, and serialization are polynomial. An arbitrary malicious invalid row sequence may generate nonproduct states; Open need not evaluate such states. No terminal projector, online evaluator or issuer, shared preimage, or native signature forgery assumption is used for correctness.

The attempted simulator was to replace each dense matrix by an independent random invertible matrix on its full local support, keeping the actual constrained mapping only for the secret input line, and replace D by an independent random string. This is not a valid hybrid: the initial local input lines are public, and the next step below recovers further constrained input/output lines from the public matrices. Even if the matrix marginal is uniform by symmetry, the joint view is not. This is an explicit failure of the proposed full-public simulation, not a claim of indistinguishability.

## New state-only closure bypass (without factoring any row operator)

Normalize each nonzero vector by dividing by its first nonzero entry. Write a hidden vector as t times its normalized vector, with t nonzero. The initial normalized u_i and overall initial amplitude A0 are public. Track known normalized labels indexed by (wire, frontier, bit), or by the bit-independent initial/terminal symbol.

In chronological gate order, for each allowed row whose local input labels are all known, form the tensor of the normalized input vectors, multiply by the public dense matrix, and factor the *output vector*, not the matrix. The output is exactly a nonzero scalar rho_g,a times the tensor of the correct normalized output labels, since the actual hidden X differs from this normalized input by a nonzero scalar. The first nonzero output coordinate gives rho_g,a; slices through that coordinate recover every normalized output factor. Record each label under its public frontier/bit name. If already recorded it agrees exactly. Thus

    rho_g,a = product_(output occurrences) t_(i,j,b) / product_(input occurrences) t_(i,j-1,b).

The attacker is allowed to combine recovered labels which came from different incompatible prefixes. They are ordinary explicit local vectors, not a source-authenticated global state. There are only O(number of occurrences) labels and constantly many rows per gate. Induction shows that every row of every actual consistent accepting stream is accessible in this closure: its predecessor labels would have been discovered earlier. The closure does not require knowing which accepting stream exists. On any TRUE instance it therefore recovers each terminal normalized vector, and has the rho ratio of every row on at least one genuine stream. This is a classical public computation, not representation-only extraction from an adversary.

The scalar still matters. Define an integer linear system on variables m_g,a for the accessible rows, with one equation sum_a m_g,a=1 per gate and a balance equation for each interior wire frontier and bit: total outgoing weight of that label at its production gate equals total incoming weight at its consumption gate. Include no nonnegativity constraint. Any globally valid accepting stream gives a 0/1 integer solution; therefore the system is integer-feasible on every TRUE instance. A standard polynomial-bit-complexity integer linear equation solver (e.g. Smith normal form with solution transforms) finds an integer solution, without solving the nonnegative 0/1 feasibility problem. No lattice hardness assumption, discrete-log computation, or representation extraction. Signed coefficients can be exponentiated with polynomial-bit exponents and inverses. This is a mathematical algorithmic argument; the generic integer solver was not executed in this run.

Multiply public ratios with these weights:

    A0 * product_(g,a) rho_g,a ^ m_g,a = product_i t_(i,terminal) = A_target.

All interior scalars cancel by the balance constraints; at each initial and terminal occurrence the bit-independent scalar has multiplicity one by the per-gate sum. Thus the attacker recovers the exact target V including its amplitude, hashes it and unmasks S on every TRUE instance in polynomial time, including an ensemble with hard original witness search if one exists. No accepting original certificate is required. The argument is independent of cryptographic properties of the hash and works on the exact public matrix serialization. The predecessor's integer marginal method needed factorization of the row *operator*; here matrices are independently dense and do not factor, but the chosen valid-state transition invariant exposes normalized output factors and scalar ratios instead. The theorem is limited to product states with publicly constructible local factors; it does not cover arbitrary globally entangled states. A secret independent per-wire change of basis can simply be absorbed into the sampled local vectors and dense operators.

## Concrete FALSE cycle countercheck

A bounded-arity compiler variant allowing binary inequality checks admits the false conjunction x!=y, y!=z, z!=x. All six allowed rows are accessible in the above closure. The equal half weight on the two rows of each constraint satisfies the balance equations rationally, but no globally valid stream exists. Multiplying every recorded rho once yields (A_target/A0)^2 exactly. With p=3 mod 4 recover the two possible amplitudes via one exponentiation and its negation; the public native VK/message tests the two candidate signature decodings. At least one is the exact frozen S, if D uses this target. This is not a claim that the actual BTC/SYS relation is this toy or that all FALSE instances admit this particular attack. The TRUE-instance integer balance argument does not rely on this toy or on p=3 mod 4. The point of this fixture is to demonstrate exact target recovery from dense non-Kronecker rows even when not a single globally consistent row stream exists, with no operator factorization.

Executed bounded JavaScript checker twice using V8 (no external packages). It constructs fresh independent dense invertible 4x4 row matrices, confirms all six are non-Kronecker by a nonzero minor of their realignment, gives the attack only canonical initial factors, overall initial scalar and public rows, and verifies the actual terminal tensor is among two exact candidates on this FALSE conjunction. Deterministic fixture randomness is not a cryptographic RNG. No actual native signature, KDF test, real source witness or QPT experiment. Exact second captured output:

```json
{"valid":0,"nonKroneckerRows":6,"accessibleRows":6,"ratios":[9,73,32,78,42,70],"squared":66,"target":[13,42,48,60,83,78,45,82],"candidates":[[13,42,48,60,83,78,45,82],[90,61,55,43,20,25,58,21]]}
```

Exact checker (run by a V8 runtime; replace final console.log by the host output callback if needed):

```js
function checker(){
  const p=103, mod=x=>((x%p)+p)%p;
  const pow=(x,n)=>{let y=1;for(;n;n=Math.floor(n/2),x=mod(x*x))if(n%2)y=mod(y*x);return y};
  const inv=x=>{if(!x)throw Error("zero");return pow(x,p-2)};
  let seed=932017;const rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%p};
  const assert=(b,msg)=>{if(!b)throw Error(msg)};
  const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  const kron=(a,b)=>a.flatMap(x=>b.map(y=>mod(x*y)));
  const mv=(A,x)=>A.map(r=>mod(r.reduce((s,v,j)=>s+v*x[j],0)));
  const mm=(A,B)=>A.map(r=>B[0].map((_,j)=>mod(r.reduce((s,v,k)=>s+v*B[k][j],0))));
  function inverse(A){
    let n=A.length,M=A.map((r,i)=>r.concat(Array.from({length:n},(_,j)=>+(i===j))));
    for(let j=0;j<n;j++){let k=M.findIndex((r,i)=>i>=j&&r[j]);if(k<0)return null;[M[j],M[k]]=[M[k],M[j]];let z=inv(M[j][j]);M[j]=M[j].map(v=>mod(v*z));for(let i=0;i<n;i++)if(i!==j){let c=M[i][j];M[i]=M[i].map((v,k)=>mod(v-c*M[j][k]))}}
    return M.map(r=>r.slice(n))
  }
  function basis(x){for(;;){let A=x.map(v=>[v,...Array.from({length:x.length-1},rnd)]);if(inverse(A))return A}}
  function vec(){return [1+rnd()%102,rnd()]}
  function norm(x){let k=x.find(v=>v!==0);return x.map(v=>mod(v*inv(k)))}
  function factor(z){let k=z.find(v=>v!==0),i=z.findIndex(v=>v!==0),a=Math.floor(i/2),b=i%2;
    let u=norm([z[b],z[2+b]]),v=norm(z.slice(2*a,2*a+2));assert(eq(z,kron(u,v).map(t=>mod(t*k))),"factor");return {u,v,k}}
  // FALSE: x!=y, y!=z, z!=x. Independent wire/stage/bit states.
  let start=Array.from({length:3},vec),end=Array.from({length:3},vec),mid=Array.from({length:3},()=>[vec(),vec()]);
  const gates=[[0,1],[1,2],[2,0]],rows=[[0,1],[1,0]];
  let seen=[0,0,0],pub=[];
  for(let [i,j] of gates){
    let first=[seen[i]===0,seen[j]===0];
    let table=rows.map(([a,b])=>{
      let x=kron(first[0]?start[i]:mid[i][a],first[1]?start[j]:mid[j][b]);
      let y=kron(first[0]?mid[i][a]:end[i],first[1]?mid[j][b]:end[j]);
      let A=mm(basis(y),inverse(basis(x)));assert(eq(mv(A,x),y),"Build transition");
      // Realigned 4x4 row matrix. Rank >1 certifies non-Kronecker.
      let R=Array.from({length:4},(_,q)=>Array.from({length:4},(_,r)=>A[2*Math.floor(q/2)+Math.floor(r/2)][2*(q%2)+r%2]));
      let nonprod=false;for(let a=0;a<4;a++)for(let b=a+1;b<4;b++)for(let c=0;c<4;c++)for(let d=c+1;d<4;d++)if(mod(R[a][c]*R[b][d]-R[a][d]*R[b][c]))nonprod=true;
      assert(nonprod,"row unexpectedly Kronecker");return {a,b,A}
    });pub.push({i,j,first,table});seen[i]++;seen[j]++;
  }
  // Public attack input: canonical starting factors, global amplitude, public rows only.
  let initial=start.map(norm),amp=start.reduce((a,v)=>mod(a*v.find(t=>t!==0)),1);
  function attack(initial,amp,pub){
    let labels=initial.map(v=>({u:v})),ratios=[];
    for(let {i,j,first,table} of pub){
      for(let {a,b,A} of table){
        let l=labels[i][first[0]?"u":String(a)],r=labels[j][first[1]?"u":String(b)];
        if(!l||!r)continue;
        let {u,v,k}=factor(mv(A,kron(l,r)));ratios.push(k);
        for(let [w,key,val] of [[i,first[0]?String(a):"v",u],[j,first[1]?String(b):"v",v]]){
          if(labels[w][key])assert(eq(labels[w][key],val),"inconsistent line");labels[w][key]=val;
        }
      }
    }
    assert(ratios.length===6,"all rows accessible");
    let squared=ratios.reduce((a,v)=>mod(a*v),mod(amp*amp));
    let r=pow(squared,(p+1)/4);assert(mod(r*r)===squared,"square root");
    let line=labels.map(l=>l.v).reduce(kron,[1]);
    return {ratios,squared,candidates:[r,mod(-r)].map(s=>line.map(v=>mod(s*v)))}
  }
  let out=attack(initial,amp,pub);
  let valid=0;for(let x=0;x<2;x++)for(let y=0;y<2;y++)for(let z=0;z<2;z++)valid+=+(x!==y&&y!==z&&z!==x);
  assert(valid===0,"FALSE");
  let target=end.reduce(kron,[1]);assert(out.candidates.some(v=>eq(v,target)),"exact target among two");
  return {valid,nonKroneckerRows:6,accessibleRows:out.ratios.length,ratios:out.ratios,squared:out.squared,target,candidates:out.candidates};
}
console.log(JSON.stringify(checker()));
```

## Next construction boundary

This removes the motivation to increase random complement noise or use independent dense matrices on the same product-state invariant. A genuine nonfactorable *state* encoding would need a classical polynomial honest representation, local public transitions, exact target canonicalization and a joint simulator that prevents recovering or transplanting state components even after adaptive access to the entire public capsule. Global hidden entanglement alone is not that construction. The attack above does not establish impossibility of such a representation, nor of computational hash-only source-dependent release. No arbitrary-QPT FALSE/hard-TRUE proof, multi-capsule/source-retention/auxiliary theorem, malicious setup or accepted native forgery reduction achieved. Preserve all original three independent OR grounds, relevant authenticated histories and actual LC maturity, finite burn refutation, exact BTC cumulative work, tag-fault typing, R316 correction, R225 endpoint scope and offline one-honest setup. Do not count this as the missing advance; no ordinary progress comment.
