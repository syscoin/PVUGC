# Noncommutative source-state transport: constructive screen, NONQUALIFYING

## Continuity and provenance

Actual open draft PVUGC PR #1 head at start: 006a53fb7c4afcb84deadf4709951b8d648b7771, branch research/pq-wkem-validation-20260918. Read the live setup audit note (blob 479ffa927e6aecd962a9c1f185cde1add2225422) and the source-ID-tree note. Top-level issue comments since 2026-11-20 were empty. No external literature, Core source/test execution, real source certificate, native signature, FE implementation or quantum proof was used.

## Named candidate and mathematical change

The R366 commutative clause-product scheme leaked its common key through 2- and 3-covers composed of inconsistent local assignments. This screen replaces commutative scalar gauges with **ordered noncommutative boundary states** to force a single assignment to persist between clauses. It is not a scalar-modulus, tensor-rank, hash-domain or parameter re-run.

Take Boolean source-verifier predicates c_j on local variable subsets S_j, and a sequence of invertible frames L_j(w) depending on the ENTIRE candidate certificate w. Define

    G_j(w) = L_(j-1)(w)^(-1) Q_j(w|S_j) L_j(w)
    Q_j(a) = I when c_j(a)=1, and 0 otherwise.

The ordered product, when all factors use exactly the SAME w, telescopes to

    PRODUCT_j G_j(w) = L_0(w)^(-1) (PRODUCT_j Q_j(w)) L_m(w).

If every clause accepts, setting the terminal relative frame to a frozen secret K gives a common value for all qualifying w. If any clause rejects, zero is absorbing. An inconsistent sequence of local clause assignments w_j introduces uncanceled junctions L_j(w_j)L_j(w_(j+1))^(-1), so the specific commutative balanced-cover identity is not automatically valid. This is an algebraic *candidate*, not a security claim.

## Precise failure of the attempted practical public serialization

For a published local clause gadget indexed only by a=w|S_j, an omitted bit z cannot affect the gadget. In a separated boundary factorization A_(j-1)(z), A_j(z), the necessary omitted-bit consistency condition is

    A_(j-1)(0)^(-1) A_j(0)
      = A_(j-1)(1)^(-1) A_j(1) = U_j.

Equivalently, A_j(b)=A_(j-1)(b) U_j for both b. Such a local transition carries the omitted bit unchanged but DOES NOT cryptographically bind that bit to an authenticated global source certificate. Otherwise the claimed local gadget actually depends on z and must carry a global state or index more input values. Merely accepting a user-supplied state identifier or independently checkable wrapper cannot prevent a malicious user from mixing internal states.

If every full global frame is publicly computable, a literally fixed exposed terminal frame K is available from any syntactic assignment, not just a valid source witness. If those frames stay secret, a future witness cannot evaluate this public capsule. Directly enumerating all full-witness transition states is exponential. A compact stateful implementation of the missing protected input-state transition would be the source-conditioned FE/WE release mechanism we have not instantiated. Noncommutativity alone is not that implementation.

This is a narrow disposition of this explicit global-frame/locally indexed representation. It is NOT a theorem against all noncommutative or hash-only constructions. No source/hash security break or unproved lower bound on SHA circuits is asserted.

## Executed bounded algebraic check

The attached standalone Python checker used noncommuting GL(2,F_101) matrices as an *algebraic* stress test, NOT a cryptographic primitive. In 500 independent random boundary pairs, omitted-bit transports differed for z=0 versus z=1. With 500 pairs purposefully correlated as A_j(b)=A_(j-1)(b) U, both transports equaled U. Two complete executions produced byte-identical JSON. This confirms the displayed conditional identity only, not any FE security, hash reduction, or ORIGINAL source admission.

Local checker SHA256: 937c2975262cd4fd31495a0cecdd0a7593fdd37e4f7332ed9139f75a72096996.
Two local outputs SHA256: 7dcb67b466b34a8db1f0fa131b784c06164e8941ee0d70f320d01fb4ed13d255.
The code and outputs are included in this research checkpoint. No other test was run.

## Unfinished operation

Still missing classical practical serialized Build_orig(x_W,sigma_cancel)->C, with PUBLIC Open_orig(C,w)=the SAME frozen safe native capability for EVERY qualifying ORIGINAL authenticated w. The original three OR branches, strict contextual AuxPoW, actual claim-prefix ancestry, BTC anchor/work, specific burn state, LC depth, claim/outpoint/deadline/reset and native message/VK binding are unchanged. A complete joint-public FALSE/hard-TRUE QPT recovery/forgery-to-ORIGINAL-certificate or independently justified hash/native break remains unproved, as do malicious one-honest setup and sibling/auxiliary composition.

A constructive successor must make the global input-state transition cryptographically source-conditioned, publicly serializable in polynomial time, and nonspliceable. No private label generator, ideal function gate, syntactic source-ID, oracle, public accept bit, or enumerated full-state table is counted as that missing advance.

NONQUALIFYING. No progress comment, user breakthrough notification, production edit, Core change, deployment, or automation change.
