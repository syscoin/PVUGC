# R149 — modular denominator clearing for ORIGINAL ideal-LWE release

**Status:** Negative architecture qualification; NOT a secure ORIGINAL-witness WKEM and not constructive progress. Do not send a routine user update. No optimization.

**Provenance:** PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, observed starting HEAD c46e744c56ee960a6784f383b432ed252d9c1467. Exact input R148 note blob c4c22093aa03675e40a9cbed6f3e418cbffa80a0 and R147 note blob 669cdee1514b5490071759379aba42a25717c7ed were read. Latest ordinary PR comment observed 6698876958. Bounded offline Node 22 checker below passed 342658 assertions, and independent Python 3 standard-library checker passed 211433 assertions. No external web/literature, entire PR diff, independent agent, production change, or deployment.

## Candidate source (classical PPT; no SOURCE oracle)

Compile the ORIGINAL verifier R(x,w), including claim/UTXO, branch, anchors/window, context and VK identity, into Boolean equations. Let M_x in Z^(N x t) have public coefficient columns for polynomial Booleanity and clause constraints; e0=(1,0,...,0). Each actual valid ORIGINAL witness w induces an integer evaluation v_w with M_x^T v_w=0 and e0^T v_w=1. Let A_x be the vertical stack [M_x^T; e0^T] in Z^((t+1) x N), and b=(0^t,1). Fix q, Delta, bit K, and errors e,eta with public support bounds |e_i|<=B_i, |eta|<=beta. Select s uniformly in Z_q^(t+1) and sample errors classically on these supports. Publish c=(A_x^T s+e) mod q and p=(b^T s+Delta K+eta) mod q.

The **full public view** also contains the ORIGINAL relation and instance, checking key, CK/J/Aux, context, native VK, and all related capsules, plus whatever adaptive permitted openings are provided. This run does NOT jointly instantiate such fields, an ordinary-LWE challenge simulator for the structured A_x, malicious N-of-N preauthorization or native signing capsule. In particular, merely saying “LWE” here is not a QPT hardness proof.

Honest OFF-CHAIN Open checks the *actual* ORIGINAL R(x,w), computes v_w, and decodes p-v_w^T c = Delta K + eta - v_w^T e (mod q), with every valid witness recovering the SAME precommitted K if dist_q(Delta,0)>2(beta+sum B_i |(v_w)_i|). This is a necessary source sketch, not an accepted secure algorithm.

## Exact modular public-denominator theorem

On any TRUE instance, run the PUBLIC rational LP minimizing E(lambda)=beta+sum B_i |lambda_i|, subject to A_x lambda=b. Its feasible set contains every honest integer v_w. Exact rational LP runs in classical polynomial time on polynomial-size rational input; an optimal rational lambda* has E(lambda*)<=E(v_w) for every valid w.

Let d>=1 clear the denominators of lambda* and a=d lambda* be integral. Then A_x a=d b, with d and a having polynomial binary length. The **witness-free, polynomial-time public** computation

    z = (d p - a^T c) mod q
      = (d Delta K + d eta - a^T e) mod q

has noise magnitude bounded by T=d E(lambda*), on EVERY supported error tape, even for arbitrarily correlated e,eta. For a binary capability, if dist_q(d Delta,0)>2T, nearest-neighbor circular decoding of {0,d Delta} recovers K with probability exactly 1 on all permitted tapes. This is a classical attack and therefore also defeats any arbitrary-QPT claim for this affine SOURCE in that parameter region. In particular, Delta>2E(lambda*) and q>2d(Delta+E(lambda*)) suffice, although the exact circular-distance test can be much sharper. A large q **alone** is not sufficient.

The attack uses only (A_x,b,c,p), so extra public checking fields, sibling capsules or quantum advice cannot make it unavailable. The attack is NOT a generic impossibility theorem for all modular LWE, all source encodings, or witness encryption.

## Reproducible concrete cases

1. Actual small ORIGINAL formula R(x,y)=x OR y (with Booleanity), monomial basis [1,x,y,x^2,xy,y^2]. Matrix columns x^2-x, y^2-y, (1-x)(1-y). Honest Boolean evaluators at (0,1),(1,0),(1,1) have l1 norms 3,3,6. The public rational lambda=(1,1/4,1/4,1/4,-1/2,1/4) has l1=5/2. At q=65521, Delta=1024, |e_i|<=1,|eta|<=1, d=4, a=(4,1,1,1,-2,1), modular code distance 4096 and scaled error bound T=14; public K recovery succeeds on every tape. This is an EASY true fixture, not a hard-witness-search experiment.

2. A SYNTHETIC, explicitly non-generic-NP example isolates denominator clearing even when there is no shorter integral projector. Take N=5, M columns (-6,1,5,0,0), (0,0,-1,1,0), (0,0,-1,0,1), honest v=(1,1,1,1,1). Feasible lambda are exactly (1,6-5u,u,u,u). Integer u has unique minimum l1=5 at u=1: for u<=0 norm>=7, for u>=2 norm>=11. The rational LP instead has u=6/5, l1=23/5, d=5, a=(5,0,6,6,6). At q=65521, Delta=1024, |errors|<=1, the public dual decodes because dist_q(5 Delta,0)=5120>2*28. This fixture does NOT instantiate an arbitrary ORIGINAL relation or a QPT hardness assumption.

3. A synthetic “denominator resonance” escape illustrates the qualification: with first M column (-5,1,4,0,0), rational lambda=(1,0,5/4,5/4,5/4), d=4, q=4096, Delta=1024, the particular dual has d Delta=0 mod q and leaks NO K through this projection. The honest v still decodes. This is **not security**: other integral/rational projectors, joint-output attacks and structured-lattice recovery are unaddressed, and no honest complete-public LWE challenge simulator exists.

The exact published standard-library Node.js checker enumerates all 3^(N+1) bounded error tapes for 10 independently sampled s and each of two K values in every fixture, checks honest opening, the modular cancellation identity, and public decoding or exact resonance collisions. Captured output is committed separately. An independently executed stdlib Python checker and its extended derivation are LOCAL ONLY; the published JS checker is actually executed, not pseudocode.

## Rejected repair and next indispensable equation

The attempted repair was small-q denominator resonance to defeat the LP dual. It cannot be promoted: an alternate public short integral dual may still exist, and random basis changes of the PUBLIC structured M_x do not establish an ordinary-QPT-LWE reduction. This is a bounded **negative architecture test**, not genuine positive ORIGINAL-dependent progress.

Needed: a classical-PPT, genuinely ORIGINAL-dependent Comp(R,x) with real jointly simulatable SOURCE keys/openings and complete checking/auxiliary/related-capsule correlations under independently justified QPT assumptions, such that every R(x,w)=1 opens the SAME precommitted native capability. Arbitrary unauthorized final-key recovery or accepted native forgery must imply an ACTUAL ORIGINAL witness or independent QPT break without demanding an adversary-volunteered internal vector. FALSE-instance security, hard-TRUE extraction, malicious N-of-N setup and abort/DA, actual source SYS/BTC chain/fork evidence constraints and the hypothetical native PQ Bitcoin endpoint remain unproved. Do NOT optimize this rejected source or report a breakthrough.
