# JOINT-MASK-20261114: constrained hash-share composition, checkpoint 1

Status: interactive construction attempt. No secure WKEM or breakthrough claimed. The user asked to combine existing constructions rather than repeat isolated component failures.

## Exact continuity

Observed PVUGC PR #1 open/draft/unmerged on research/pq-wkem-validation-20260918 at 63db8a67501a8ee31723ca27b616b6270bed58b9, tree da429300232b882508ce78c7c0d8b89b93bbaaf8. Read its R288 global-witness-tweak note and the exact predecessor composition_correction_garble_20261114/RESEARCH.md (blob 72d36b9c2d8c1e3b82200e162e6b63e03ebe2732). The latest ordinary-comment query since 2026-11-14T00:00:00Z returned no comments. No broad historical sweep, external literature, new source-consensus assertion, or independent research agent. Daybreak tools were discovered and its access bootstrap read; no scan has been launched or credited.

## What is being combined differently

The earlier composition garbled a full correction function S XOR H(F_1(w) XOR ... XOR F_m(w)) and exposed constrained keys for the F_i. Its known-value cut enabled mixing locally valid witnesses and immediate decryption.

This attempt removes that correction program. Split a frozen secret K as XOR_i k_i. For a graph G on the verifier's local constraints C_i and each edge e choose one independent private SHA-based function R_e(w). Publish independently garbled local share evaluators restricted to a satisfying subcube of C_i:

    Y_i(w) = k_i XOR XOR_{e incident to i} R_e(w).

A valid ORIGINAL witness w supplies one allowed local encoding for EVERY i. Each R_e(w) then occurs twice, and XOR_i Y_i(w)=K. The same K can seal one frozen, claim-scoped native cancellation signature. Distinct valid witnesses have distinct masks but identical output; no future-witness enumeration is needed for this algebraic correctness identity.

An actual local evaluator is to be a garbled SHA circuit with private seed/share bits fixed to ONE active label each, public input label pairs only for locally unconstrained witness bits, and fixed active labels for the selected local satisfying pattern. Separate satisfying patterns get independently garbled programs. This is NOT an ideal restricted oracle; ordinary garbling is the concrete representation to be checked. No full original SHA/AuxPoW circuit is asserted implemented in this checkpoint.

## Security-critical experiment and repair

First use a cycle of constraint nodes. The attacker is NOT assumed to know the ordinary values of internal R_e outputs. Test whether it can select two locally allowed inputs per local program, copy genuine opaque labels from its own evaluations, and make the private masks cancel across different programs. This tests a stronger composition failure than merely exposing the mask itself.

Repair attempt: use a complete graph, not just adjacent masks. Then selecting one satisfying subcube per constraint with every pair compatible would entail a globally compatible Boolean assignment. But arbitrary public reuse allows several outputs per constraint, so this argument alone is insufficient. Test parity/odd-multiplicity combinations on a genuinely unsatisfiable finite constraint system, keeping each local hash-cut input inside that local program's actual permitted subcube. No security claim is made from blocking only the first attack.

If necessary, examine threshold/vector masks: whether one shared witness must be used across ALL mask coordinates, and whether replacing that binding with a garbled circuit restores mixed-coordinate attacks. A premise that secretly supplies reusable, authenticated, witness-bound evaluation is not an independent solution.

## Unchanged ORIGINAL conditions

Use the approved three OR cancellation grounds; all authentic source/claim/UTXO/native-message/anchor/window/LC-depth bindings remain inside the target source relation. Post-PQ Core #609 canonical tags and modern chain ID are preserved. Wrong-wrapper evidence is not a valid fork, different parents for one child are not automatically different outcomes, and raw work is not canonical Bitcoin membership. The existing N-of-N preauthorization/honest-erasure ceremony is not an online challenge quorum. Bitcoin receives native cancellation authorization only, no original verifier or computation dispute. No source-secret issuer, new opcode, group/lattice foundation, or automatic QPT lift is introduced.

This checkpoint records equations and an actual planned construction experiment before execution. It does not assert a checker has run, that source-conditioned release works, or that a native endpoint or malicious setup is secure.
