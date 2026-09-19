# Public witness transfer after planted matrix programming

**No completed generic PQ WKEM or witness-transfer compiler is supplied.**

This continuation starts from `2bb4e584e8c22fc259cdb79da2e092344b49cbf0` and the supplied joint-programming note. Only supplied files and the requested GitHub record were used. No outside literature, priority claim, production change, or secure parameter recommendation is involved.

## 1. What planting does not supply

The preceding sampler chooses a secret z*, a nonzero y, and samples V uniformly subject to Vz*=y. Its exact spectral statement is

    E_V sum_(Va=y, a!=z*) |muhat(a)|^2 = beta*.

It does not generate a public Prove(pk,x,w) that gives a future valid source witness access to z*. Adding public proving material needs its own security proof: pk=z* defeats secrecy, while pk empty supplies no generic source-witness prover. The matrix marginal cannot establish the security of either augmented public view.

## 2. Useful proof outputs are forced to be canonical

Call a target preimage gamma-useful when |muhat(a)|>=gamma. Every useful a!=z* contributes at least gamma^2 to the nonnegative other-preimage mass. Hence

    Pr[there exists any gamma-useful a!=z* with Va=y] <= beta*/gamma^2.

Except for this setup event, every successful useful proof output is z*, for every witness and proving tape. This is a statement about all vectors, not a fixed-prover union bound. If z* is useful too, the useful set is exactly {z*} on those setups.

For a fixed valid source witness whose prover returns a useful vector with probability >=1-epsilon, it returns z* with probability >=1-epsilon-beta*/gamma^2. Arbitrary proving information computed from V does not change the pointwise statement; additional conditioning/rejection of V changes the setup law and requires new analysis.

This result does not construct the canonical prover.

## 3. Attempted simulated-OR completion

### Linear responses

For a public linear commitment map A, a simulator can select response s, nonzero challenge c, and define commitment

    t=A*s-c*y.

If a source witness gives a vector u(w), candidate coins r=s-c*u(w) satisfy

    A*r=t  iff  A*u(w)=y.

Thus recovering simulator coins already requires the fixed-preimage witness encoding. This identity is useful when that encoding exists, but does not create it for arbitrary NP.

### Quadratic responses

For a homogeneous quadratic map Q with polarization B,

    Q(s-c*u)=Q(s)-c*B(s,u)+c^2*Q(u).

Even if Q(u)=0, the witness-dependent B(s,u) remains. A simulator can choose ell and a=Q(s)-c*ell, yielding an accepting transcript equation Q(s)=a+c*ell. But r=s-c*u opens a only when B(s,u)=ell. Simulated acceptance does not imply that all valid witnesses can open the same commitment.

Concrete example over an odd prime field:

    Q(u0,u1,u2)=u0*u2-u1^2,
    s=(0,1,0), u(v)=(1,v,v^2),
    B(s,u(v))=-2*v.

All u(v) are valid. A fixed label selects exactly one v. Over F5 with c=1, ell=0 gives a=4: u(0) recovers coins with Q=4, while u(1) recovers coins with Q=1.

These are tests of a proposed transfer step, not attacks on an existing deployed proof system. Q alone is an easy toy relation.

### Explicit label tables

For n copies of this fixture with v_i Boolean and the same fixed response, required label vectors (-2*v_1,...,-2*v_n) have exactly 2^n distinct values. An explicit fixed-response table with one label vector per transcript, covering every such witness, needs 2^n transcripts.

This is not a lower bound for all public provers. Different responses, canonicalization, or a new succinct cryptographic representation are outside the premise. Degenerate responses also remove the injective-label premise. Publishing independent per-equation tables does not, by itself, enforce that their openings come from one globally consistent source witness.

## 4. Conditional simplification of the outer layer

Suppose an actual construction supplied

    Setup(R,x) -> (P,z*),
    Prove(P,x,w) -> z* for valid w,

with an independently proved joint-public-output and source-extraction theorem. P is the base header generated before the release key. It is independent of a fresh release random oracle H; other proof-oracle domains are separated.

Then the core hash wrapper is simply

    header = P,
    K = H(Encode(P,z*)),
    Decap(P,w) = H(Encode(P,Prove(P,x,w))).

Encode is canonical and injective. Subsequent key-dependent ciphertexts or checkers are not recursively included in the base-header input to H. With the approximate useful-preimage prover of Section 2, correctness loses at most epsilon+beta*/gamma^2.

This would eliminate the harmonic channel and outer code for this exact plant-transfer regime. It is conditional on the MISSING prover, not a completed encryption construction.

## 5. Quantum random-oracle bridge with explicit loss

Sample (P,z*) independently of H, set x*=Encode(P,z*), and choose independent uniform comparison key K. Compare

    ideal: A^H(P,K),
    real:  A^H'(P,K), where H'(x*)=K and H'=H elsewhere.

The real joint distribution is exactly that of a random oracle with its value at x* supplied as K.

Let A make Q>=1 queries. In the ideal execution let p_j be the squared query amplitude on x* before query j. A reduction given P chooses K independently, runs A with the independent oracle, chooses a uniform query index j, and measures that query input. It returns the parsed candidate z for a query with base-header prefix P. Its probability of returning z* is

    p=(1/Q)*sum_j E[p_j].

The reduction need not know z* to run; success is assessed by the experiment.

For each fixed setup/oracle/coin choice, telescope the products of query and circuit unitaries. The j-th difference has an ideal-oracle prefix and a reprogrammed-oracle suffix. The two query unitaries differ only at x*, so this term has norm at most 2*sqrt(p_j). The final state distance is at most 2*sum_j sqrt(p_j). Measurement probability difference is at most this norm. Averaging and Cauchy/Jensen yield

    Delta <= 2Q*sqrt(p),
    p >= Delta^2/(4Q^2),

where Delta is the distinguishing-probability gap. This is a QROM result with circuit access and prepared allowed auxiliary information, not a standard-model theorem for a concrete hash or access to an unknown external quantum-advice state.

### Whole-key recovery

For an adversary that is not handed K and tries to recover it from the core header, use the decision predicate 'adversary output equals comparison K'. In the ideal game its success is 2^-kappa. Thus recovery success epsilon implies plant recovery probability at least

    (epsilon-2^-kappa)_+^2/(4Q^2).

A separately proved inner source-extraction theorem could then be invoked on this plant-recovery algorithm. The present work has not supplied that theorem or its actual public prover.

### Key-dependent auxiliary data

For specified extra data Aux(P,K;r), form it from the SAME comparison K in both oracle games. If ideal key-recovery success is p_ideal, the corresponding bound is

    p_plant >= (epsilon-p_ideal)_+^2/(4Q^2).

Bounding p_ideal requires its own symmetric/signature/auxiliary-security analysis. It is not automatically 2^-kappa. Secret-state-dependent MPC transcripts or data the reduction cannot generate are not silently covered. The inner extraction theorem must permit the resulting algorithm and its auxiliary information.

A header with an efficiently testable checker of the real key cannot also have ordinary real-or-independent-random candidate-key indistinguishability: an adversary handed a candidate can check it. This does not disprove one-way key hiding or conditional authorization. The security games must be kept distinct.

## 6. Actual checks and uncompleted result

Twelve test groups passed and passed an isolated-directory replay with matching hashes/counts. Selected scopes:
- 480 linear simulator/preimage equivalences;
- 32,708 exact quadratic expansion identities;
- 1,622 witness-opening checks;
- 2,046 explicit cover labels across the fixtures;
- 196 programmed matrices and 784 matrix/threshold checks;
- eight exact other-mass expectations;
- 816 small statevector oracle comparisons over nine averaged experiments;
- seven exact programmed/real oracle joint distributions;
- negative controls for zero challenges, degenerate responses, oracle-correlated auxiliary input, and candidate-key/checker definitions.

Finite-field checks are exact. Statevector comparisons use NumPy with tolerance 1e-10; the analytic proof, not that tolerance, establishes the general inequality. No quantum hardware, cryptographic-size attack, or secure parameter set was tested. Replays are not additive coverage.

The complete local sources/results are in the conversation artifact `wkem_public_prover_audit.zip`. This documentation commit does not claim those test files were also committed.

Local source SHA-256:
- checks.py: `e81138bc70cbbc9a40c49f360890d73d235b24335260582206e1bc787a48dbb1`
- test_checks.py: `9dcbf431d8f184f5b4b9eef3a9364d4a46268b360ef02cfb4ee0e3c3c0b79ea7`

**Uncompleted:** the source-witness-to-planted-secret public compiler, its full-output PQ hardness/source-extraction reduction, allowed setup/auxiliary composition, and the requested efficient generic WKEM. No new assumption asserting those properties is being substituted for their construction.
