# Run 80 — QPT audit of Tsabary lattice witness encryption: what is and is not post-quantum

**Status:** adversary-model audit, a conditional QPT-lifting lemma for a straight-line static-ciphertext proof skeleton, and a literature-based rejection of the original broad Assumption 31 as an acceptable foundation. **Not a completed generic-NP PQ witness KEM.**

Starting verified PR head: `c4a33a018607bda7d8e8b1d646d54df9c399e22e`.

This run follows the user's clarification that the target is a **classical public/offline implementation secure against arbitrary QPT adversaries**. Honest setup/encapsulation/decapsulation may be ordinary classical PPT algorithms. What is not sufficient is a security theorem quantified only over classical PPT attackers.

No production path is changed.

## 1. Executive classification

Tsabary, *Candidate Witness Encryption from Lattice Techniques* (CRYPTO 2022), is an important architectural lead but its published security theorem does **not** establish the post-quantum property required here.

| Component | Honest / proof model in the paper | What it establishes | QPT status for this project |
|---|---|---|---|
| Enc/Dec | classical probabilistic polynomial time | correctness / efficiency | compatible with PQ security |
| Generalized/relative LWE definitions | classical PPT distinguishers with indexed classical queries | classical computational hardness relation | not a QPT theorem |
| Standard LWE component | classical formulation; paper recalls reductions relating suitable LWE parameters to quantum hardness of SIVP | standard-LWE part of classical hybrid | can be instantiated with a separate QPT-LWE assumption/reduction, but exact parameters must be checked |
| Assumption 31 | classical PPT relative-hardness assumption on correlated trapdoor/prefix distributions | converts malicious use of trapdoor samples to semi-honest accessible matrices | no QPT theorem; not implied by ordinary LWE |
| Corollary 1 | any PPT adversary | false-statement message hiding | classical only |
| Source extraction | none | ordinary WE hiding, not proof of knowledge | missing even classically, hence also missing for QPT |

The word "lattice" is therefore not enough to call this WE construction quantum-safe.

Primary source:
Rotem Tsabary, *Candidate Witness Encryption from Lattice Techniques*, CRYPTO 2022, DOI 10.1007/978-3-031-15802-5_19.

## 2. What the paper actually quantifies over

The generalized relative-hardness definition says: for **any PPT distinguisher** `D` there exists a **PPT distinguisher** `D'` satisfying the stated advantage relation. Its indexed oracle accepts an index and returns the corresponding fixed-error LWE sample; the discussion explicitly observes that a PPT distinguisher can inspect only polynomially many members of the exponentially large indexed family.

Assumption 31 then samples `(A,A_TD) <- TrapGen`, permits `aux,T,S,B` to be arbitrarily correlated with `A,A_TD`, samples the trapdoor preimage `K <- A_TD(T)`, and assumes

    LWE[B ∪ {S A}, (K,aux)]
       <=
    LWE[B ∪ {S A, S T}, aux] + negl.

This is the special extra assumption needed to justify the hidden-state transition encodings.

The final security corollary is explicitly quantified over **PPT adversaries** and assumes Assumption 31 plus standard decisional LWE. It is a false-instance hiding theorem; it is not an extractor for attacks on true instances.

The paper also recalls a parameter regime where solving its standard-LWE problem would imply algorithms for worst-case lattice problems including a quantum-hardness statement for SIVP. That is relevant evidence for the *standard LWE component*. It does not turn Assumption 31 into a quantum assumption and does not change the adversary quantifier in the WE corollary.

## 3. Later work materially changes how Assumption 31 should be treated

Brzuska, Ünal, and Woo, *Evasive LWE Assumptions: Definitions, Classes, and Counterexamples* (ePrint 2024/2000; ASIACRYPT 2024), systematically studies these variants.

Their updated manuscript states that, based on standard LWE, they construct counterexamples against three private-coin evasive-LWE variants, including the variant used by Tsabary. In the Tsabary-specific discussion they say Counterexample 3 applies to the broad evasive-type assumption where the sampler inputs `B` and its outputs can be arbitrarily correlated with `B`.

That means the **broad universal form** of Tsabary's Assumption 31 is not an acceptable assumption for this project even before asking about quantum attackers.

There is an important qualification. The same paper observes that in Tsabary's *actual construction sampler*, knowledge of `B` and its trapdoor appears to be used only to sample preimages, while `aux` contains no additional components correlated with that trapdoor. They therefore say the construction may plausibly be provable under a narrower private-coin evasive-LWE variant that avoids their counterexamples.

They do **not** provide that proof. They explicitly note that Tsabary's exponential indexed distributions and oracle interface make the adaptation nontrivial and leave verification of the construction to future work.

Therefore the correct status is:

1. do not assume Assumption 31 as originally stated;
2. do not claim the Tsabary construction itself is broken;
3. isolate the exact restricted distribution used by the construction;
4. either reduce that restricted statement to independently justified QPT-hard assumptions or abandon this route.

This is substantially stronger caution than merely saying "the assumption is nonstandard."

## 4. Derived conditional QPT-lifting lemma for static classical ciphertexts

There is nevertheless a useful architectural fact.

### Lemma — straight-line classical-distribution hybrids are QPT-preserving conditionally

Consider a static classical ciphertext security game with a hybrid chain

    H_0, H_1, ..., H_M

of classical distributions.

Assume that for every computational neighboring pair `(H_j,H_{j+1})` there is a black-box straight-line reduction which:

* receives the corresponding challenge,
* makes only **classical** challenge/oracle queries,
* constructs a classical sample for the adversary,
* invokes the adversary once as a QPT subroutine,
* outputs its final classical bit,
* performs no rewinding, no measurement of the adversary's private state, and no random-oracle programming.

Assume the relevant base challenge is hard against QPT reductions of exactly that interface.

Then the same hybrid proof bounds every QPT adversary by the sum of the QPT neighboring advantages plus the statistical distances of information-theoretic neighboring pairs.

### Proof

A QPT adversary receiving a classical sample `x` has some acceptance probability

    q(x) in [0,1].

For two classical distributions `P,Q`,

    |E_P q - E_Q q| <= TV(P,Q).

Equivalently, the density matrices presented to the QPT adversary are diagonal in the computational basis and their trace distance equals the classical total variation distance.

For a computational adjacent pair, the assumed straight-line reduction can run the QPT adversary as a subroutine without copying, rewinding, or inspecting its private state. Therefore any QPT distinguishing gap for that pair gives the same gap against the QPT base assumption.

Finally,

    |Pr[A(H_0)=1]-Pr[A(H_M)=1]|
      <= sum_j |Pr[A(H_j)=1]-Pr[A(H_{j+1})=1]|.

No random oracle is present in this argument. ∎

### Scope

This lemma is generic. It does **not** prove that every omitted step of Tsabary's full proof has the required straight-line form.

The proceedings version says the full proofs of its two main lemmas are in a full version; the visible proof overview is dominated by classical distribution hybrids, statistical "error swallowing," and direct reductions. I did not find a visible rewinding or QROM step. That makes a conditional QPT lift of the *architecture* plausible, but not established.

## 5. Classical-index oracle versus coherent quantum oracle

Tsabary's generalized LWE experiment gives the distinguisher indexed access to an exponentially large family of classical samples. Its formal interface is a classical index query, and the paper relies on a PPT adversary seeing only polynomially many indices.

There are two different quantum statements one could ask for:

1. **classical-index QPT relative hardness:** the distinguisher may perform arbitrary quantum computation, but its requests to the indexed LWE challenger are classical indices and responses are classical strings;
2. **coherent-query QPT relative hardness:** the challenger must support superposition queries over the index set.

The second is strictly stronger and is not defined by the paper.

For the **real static-ciphertext WE game**, a reduction may only need the first interface if it can itself make the required challenge queries classically while constructing one classical ciphertext and then invoke the QPT adversary once. This is exactly why the straight-line audit matters.

Because the proceedings version omits the full proofs of the two main lemmas, this run does not claim that the weaker classical-index QPT assumption is sufficient for every detail.

## 6. Hybrid-loss obligation becomes more severe, not less, in a QPT claim

The visible proof skeleton has two large parts.

### First step

The real-to-semi-honest conversion takes `t` layers; the paper says every layer uses `O(w)` reductions to Assumption 31. A conservative bookkeeping control is therefore

    N_extra = O(t w).

### Second step

For the false branching program, the proof iterates over all

    z* in {0,1}^t

and says every one of the `2^t` stages uses `2t` sub-hybrids. Thus

    N_LWE = O(t 2^t).

The proceedings summary itself states `O(t 2^t)` hybrids.

If each neighboring computational gap has advantage at most `epsilon`, a simple hybrid proof pays the number of hybrids:

    Adv_WE
       <= c_A t w epsilon_extra
        + c_L t 2^t epsilon_LWE
        + epsilon_stat.                                  (1)

This matters asymptotically. "Each step is negligible" is **not by itself sufficient** when the number of steps is exponential in a polynomially growing `t`. For example

    epsilon(lambda)=2^{-sqrt(lambda)}

is negligible, but if `t=lambda` then

    2^t epsilon(lambda)

is enormous.

So a complete theorem needs one of:

* `t=O(log lambda)`;
* an explicit subexponential/exponential hardness guarantee strong enough to survive the hybrid count;
* a proof that avoids the exponential hybrid loss.

This is a separate obligation from the PPT/QPT distinction.

The checker records the exact arithmetic of a conservative visible-skeleton count. For example, retaining 128 bits after a simple union bound would require about 167 per-step bits at `(t,w)=(32,256)`, 199 bits at `(64,512)`, and 264 bits at `(128,1024)`. These are bookkeeping figures, not concrete LWE estimates.

## 7. Conditional QPT statement one *could* prove — but it is not our endpoint

A defensible conditional statement would have to look like the following.

Define a **restricted actual-sampler trapdoor-prefix assumption** only for the distributions generated inside Tsabary's construction, after removing the arbitrary-correlation generality hit by the known counterexample.

Suppose:

1. that restricted assumption holds against QPT distinguishers with the exact classical-index interface needed by a straight-line proof;
2. standard decisional LWE at the exact parameters is QPT-hard;
3. the omitted proof details are straight-line/QPT-preserving;
4. all statistical-error terms are negligible at the chosen parameters;
5. the per-step hardness is strong enough to survive `O(t 2^t)` hybrids.

Then the visible proof skeleton would plausibly yield **QPT false-statement message hiding** for a static classical ciphertext.

This is a derived conditional statement from this audit, not Tsabary's theorem.

It is still not acceptable as the project's "holy grail," because item 1 is exactly a nonstandard assumption that has not been reduced to ordinary QPT-LWE/SIS, and because the conclusion is only false-statement hiding.

## 8. The larger missing theorem remains source extraction on true instances

Ordinary witness encryption asks:

    false x => Enc(x,0) indistinguishable from Enc(x,1).

Our target additionally asks:

    arbitrary QPT early FINAL-key recovery on true x
       =>
    ORIGINAL source witness
       OR
    break an independently justified QPT-hard assumption.

A QPT upgrade of Tsabary's false-instance proof would not establish this.

This distinction is fundamental. A true statement may have unusual representation-level leakage that does not contradict ordinary WE security at all. The Run-76 ideal-oracle theorem shows how key recovery can imply source extraction in a black-box predicate-oracle model, but a real public representation still needs a simulation/reduction that rules out non-oracle leakage.

## 9. Implication for our research direction

The correct constructive target is **not** "prove quantum Assumption 31."

The broad original assumption has known counterexamples. Simply quantifying it over QPT adversaries would make an already overbroad statement stronger without addressing the classical counterexample.

The useful next target is much narrower:

> Formalize the exact construction-specific trapdoor/prefix distribution, with the source trapdoor used only to generate the one required preimage and without arbitrary auxiliary correlation, and determine whether that exact transition can be proved QPT-secure from standard LWE/SIS or another independently justified PQ assumption.

The Hair–Sahai rank/source interface may be useful only if it supplies a property that rules out the malicious alternative use of the preimage **for that exact distribution**. No such reduction is currently known or assumed here.

If this restricted step cannot be justified from an independently credible QPT-hard base, the Tsabary architecture should be abandoned rather than rehabilitated by naming a new evasive-LWE assumption.

## 10. Validation actually executed

`qpt_tsabary_audit_run80_check.py` is deterministic and standard-library-only.

It validates only arithmetic/model-boundary identities:

* 600 finite controls that classical total variation equals trace distance of the corresponding diagonal quantum states;
* the acceptance gap of a random bounded functional never exceeds TV;
* 1,000 exact hybrid triangle-inequality controls;
* visible-skeleton step-count/security-loss ledgers;
* an explicit numerical control showing that a negligible per-step term `2^{-sqrt(lambda)}` can be destroyed by `2^lambda` hybrids;
* a contrasting polynomial-hybrid control for `t=ceil(log2 lambda)`.

The checker does **not** test LWE, evasive LWE, a QPT adversary, or any cryptographic assumption. Passing it is not evidence of security.

## 11. Result and handoff

### Established in this run

* PPT honest algorithms are compatible with a PQ scheme; the adversary quantifier is the critical distinction.
* Tsabary's published WE theorem is classical PPT-attacker security.
* Its standard-LWE component has a credible PQ route if instantiated under QPT-LWE hardness.
* Its special Assumption 31 has no such automatic route and its broad original private-coin formulation is covered by later counterexamples.
* The actual Tsabary sampler may plausibly fit a narrower non-counterexampled assumption, but this has not been proved.
* A straight-line static-classical hybrid proof lifts mechanically to QPT **conditional on QPT-hard neighboring assumptions and a QPT-preserving reduction interface**.
* The visible Tsabary proof has exponential hybrid loss `O(t 2^t)`, which demands concrete hardness accounting.
* Even a successful QPT false-hiding lift would still not provide our arbitrary-QPT original-source extraction theorem.

### Unresolved

* standard-assumption QPT proof for the actual trapdoor/prefix transition;
* complete QPT false-statement hiding for a construction meeting our assumptions;
* arbitrary-QPT final-key recovery to original source witness / PQ break;
* auxiliary-input and multi-capsule composition;
* malicious-secure erased setup with abort;
* practical parameters.

The stopping condition is not met.
