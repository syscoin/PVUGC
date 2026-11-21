# R125 — A public generalized-least-squares decoder defeats the proposed Gaussian affine SOURCE repair

**Classification: mathematical no-go in a limited source family, NOT an ORIGINAL-witness KEM breakthrough.** This is a foundational diagnostic, not a size optimization, an LWE break, a user-facing result, or a generic impossibility result.

**Source continuity.** syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, opening SHA dc691a81ae42cfd17b56f6e63a3c150e530bd847, draft/unmerged. R124 original block exact-version Git blob a267a5653f3554ef6f63d8ea8212434b2af9cd2d and R123 exact-version blob d24a8c5526ba0825a437e55a1429fc91f9398d68 were read. Latest substantive ordinary PR comment 6698876958. No external literature or unrelated internet search.

## Explicit continuation and source

R121–R124 tried to keep a hidden pad behind noisy ORIGINAL-dependent affine equations. This iteration asked whether replacing independent bounded errors by a public **positive-definite correlated Gaussian** noise covariance can prevent an unauthorized affine representation from opening the pad.

For a given ORIGINAL instance x, let a classical PPT compiler produce **public**, bit-independent parameters rho=(A,b,Sigma,Delta,R,context), with rational full-row-rank A in Q^(k×n), b in Q^k, rational positive-definite Sigma in Q^(n×n), and public bounds Delta,R. The proposed idealized source samples real alpha conditional on b^T alpha=h_B (h_0=0,h_1=Delta), adds independent e~N(0,Sigma), and publishes p=A^T alpha+e. An ORIGINAL valid witness w is publicly converted to z_w with A z_w=b and z_w^T Sigma z_w≤R²; its opener calculates z_w^T p and nearest-center-decodes the SAME B for all valid w. Correlated checking keys, native VK, context, auxiliary data and related capsules might be published too; p remains a marginal of the full output.

## Exact full-public attack independent of ORIGINAL witnesses

The **public** weighted minimum-variance affine solution is

  z_star = Sigma^(-1) A^T (A Sigma^(-1) A^T)^(-1) b.

This is rationally computable in polynomial time, without knowing or asking for any ORIGINAL witness or representation. For any z satisfying A z=b, set v=z-z_star. Then Av=0 and Sigma z_star belongs to rowspace(A), so

  v^T Sigma z_star = 0,
  Var(z^T e) = z_star^T Sigma z_star + v^T Sigma v >= z_star^T Sigma z_star.

Also z_star^T p=h_B+z_star^T e. As both scores have centered Gaussian noise, the nearest-center Gaussian error for the public z_star score is never greater than for ANY legitimate witness's raw linear score:

  P_error(public)=Phi(-Delta/(2 sqrt(z_star^T Sigma z_star)))
                <= Phi(-Delta/(2 sqrt(z_w^T Sigma z_w))).

This works for **arbitrary public positive-definite covariance**, not only the independent bounded errors originally attacked in R121/R122A. Adding fields to the full-public distribution or coherent quantum post-processing does not make the already-visible p marginal hide its bit. It does not apply to finite-field modular arithmetic, discrete LWE ciphertexts, nonlinear release, or secret covariance. It does not extract ORIGINAL witnesses.

## Qualified complexity consequence

Suppose a randomized classical-PPT compiler for every NP instance generates the above bit-independent public rho, a publicly known R, and every true instance has a valid-witness affine opening of Sigma-norm≤R with setup failure≤eta. Let Delta >= 2R sqrt(2log(1/epsilon)). Suppose for every FALSE instance the complete-public bit distinguishability, even just for classical PPT adversaries, is≤delta. Define the **public polynomial-time decision event** E(rho): z_star^T Sigma z_star≤R² (set E=false when the affine constraints have no solution).

For TRUE x, Pr[E]≥1-eta. For FALSE x and any rho in E, the explicit public Gaussian decoder distinguishes the hidden bit with advantage (in TV convention)≥1-2epsilon. Because rho is public and independent of B, a distinguisher can apply the decoder only on E and random-guess otherwise, giving

  Pr[E | FALSE] <= delta / (1-2epsilon).

If eta and delta are sufficiently small, sampling rho and checking E is a BPP algorithm for the ORIGINAL NP language. Thus **a universal statistically or computationally FALSE-hiding compiler of this specific real Gaussian affine form implies NP ⊆ BPP**; with deterministic setup and guarantees, NP ⊆ P. This is a conditional complexity obstruction, not proof that NP is outside BPP. The theorem requires that every ORIGINAL opening be a low-norm linear score of the displayed p with public Sigma and bit-independent rho. A specialized nonlinear decoder or finite-field error law does not satisfy its premises.

## Exact bounded checker and counterexamples

R124's fixed FALSE block has A rows
[1,1,0,0,0,0,0,0],
[0,0,1,1,1,0,0,0],
[0,0,0,0,0,1,1,1],
[0,3,0,1,2,0,0,0],
[3,0,0,0,0,0,1,2],
with b=(1,1,1,3,3). Its easy invalid integer representation z_bad=(0,1,1,0,0,0,-1,2) has Euclidean squared norm 7. In the *real Gaussian* model, the even better public rational affine score z_star=(1/2,1/2,1/12,1/3,7/12,1/12,1/3,7/12) has squared norm 17/12. Non-isotropic diagonal covariances (1,...,8) and (8,...,1) were checked by exact rational identities too.

Separately, an illustrative satisfiable affine system A=[[1,1,0],[0,1,1]], b=(1,1) has a valid binary affine vector w=(0,1,0), squared norm 1, while public z_star=(1,2,1)/3 has squared norm 2/3. This illustration is not a generic NP compiler or security experiment.

The V8 checker below was **executed** (exact integer-affine identities and Gaussian variance inequalities), and its captured JSON output is included. An independent LOCAL Python standard-library Fraction checker was also run with 43 assertions; it computes rational inverse matrices directly rather than trusting the recorded z_star vectors. LOCAL files: RESEARCH.md, checker.py, captured.json; Python file SHA-256 7b39804f19f6ca5a4a82e21e8fcc03e5deebb260ea7573276cdd325a73ee5504. These checks establish finite algebra only, not QPT-LWE hardness.

## Next obligation (NOT solved)

The candidate is rejected within its exact Gaussian-affine premises. Do not repeat covariance tuning or size work as positive progress. Any successor must actually instantiate a **nonlinear or modular/discrete ORIGINAL-dependent release** plus its complete public (R,x,capsule,J,CK,Aux,context,VK,related capsules) QPT challenge simulator from source-dependent setup/opening coins without SourceOpen. For every valid ORIGINAL w, Open(Comp(R,x),w) must return the SAME frozen native signature. Arbitrary unauthorized QPT signature recovery or accepted native forgery must yield an ACTUAL ORIGINAL witness or an independently justified QPT break; a supplied short representation, inner proof acceptance, separate marginal LWE pad argument or generic iO/WE assumption does not qualify. Malicious N-of-N ceremony, abort/graph/DA, source SYS/BTC header/AuxPoW/tag/window rules, parameter calibration and hypothetical native Bitcoin PQ remain open. No PR progress comment is warranted for this diagnostic under the user's quiet-reporting instruction.

## Exact executed JavaScript checker

~~~javascript
function checkR125(){
  let n=0;const ok=(test,label)=>{n++;if(!test)throw new Error("R125 check "+n+": "+label);};
  const dot=(a,b)=>a.reduce((t,x,i)=>t+x*b[i],0);
  const mv=(A,x)=>A.map(r=>dot(r,x));
  const A=[[1,1,0,0,0,0,0,0],[0,0,1,1,1,0,0,0],[0,0,0,0,0,1,1,1],[0,3,0,1,2,0,0,0],[3,0,0,0,0,0,1,2]];
  const b=[1,1,1,3,3],zBad=[0,1,1,0,0,0,-1,2];
  const N=[[0,0,3,-6,3,0,0,0],[-1,1,3,-3,0,-3,3,0],[-2,2,6,-6,0,-3,0,3]];
  ok(JSON.stringify(mv(A,zBad))===JSON.stringify(b),"bad integer affine solution");
  const entries=[
    {d:[1,1,1,1,1,1,1,1],den:12,num:[6,6,1,4,7,1,4,7],vnum:17,vden:12,badv:7},
    {d:[1,2,3,4,5,6,7,8],den:2907,num:[1609,1298,-71,1129,1849,452,1016,1439],vnum:18295,vden:2907,badv:44},
    {d:[8,7,6,5,4,3,2,1],den:909,num:[398,511,170,284,455,43,199,667],vnum:5533,vden:909,badv:19}
  ];
  for(const e of entries){
    ok(JSON.stringify(mv(A,e.num))===JSON.stringify(b.map(t=>e.den*t)),"weighted exact affine score");
    ok(dot(e.num,e.num.map((v,i)=>v*e.d[i]))*e.vden===e.vnum*e.den*e.den,"exact generalized variance");
    ok(dot(zBad,zBad.map((v,i)=>v*e.d[i]))===e.badv,"integer false variance");
    ok(e.vnum/e.vden < e.badv,"public decoder variance advantage");
    for(const row of N){
      ok(JSON.stringify(mv(A,row))===JSON.stringify([0,0,0,0,0]),"null-space basis row");
      ok(dot(row,e.num.map((v,i)=>v*e.d[i]))===0,"weighted orthogonality to null-space");
    }
  }
  const A2=[[1,1,0],[0,1,1]],b2=[1,1],z2num=[1,2,1],w=[0,1,0];
  ok(JSON.stringify(mv(A2,z2num))===JSON.stringify([3,3]),"true toy min decoder");
  ok(JSON.stringify(mv(A2,w))===JSON.stringify(b2),"true toy witness");
  ok(dot(z2num,z2num)===6 && dot(w,w)===1,"variance 2/3 vs 1");
  return {run:"R125-GAUSSIAN-AFFINE-SOURCE-REPAIR-20261107",assertions:n,exact_min_variance_block:"17/12",false_integer_variance:"7",conclusion:"No source-security result; Gaussian linear source family ruled out as generic construction unless NP subset BPP."};
}
const captured = checkR125();
console.log(JSON.stringify(captured));
~~~

## Captured output

~~~json
{
  "run": "R125-GAUSSIAN-AFFINE-SOURCE-REPAIR-20261107",
  "assertions": 34,
  "exact_min_variance_block": "17/12",
  "false_integer_variance": "7",
  "conclusion": "No source-security result; Gaussian linear source family ruled out as generic construction unless NP subset BPP."
}
~~~
