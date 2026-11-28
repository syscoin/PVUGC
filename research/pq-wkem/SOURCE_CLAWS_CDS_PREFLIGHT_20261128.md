# Public two-sampler source claws and conditional-disclosure preflight (2026-11-28)

Research-only intermediate result; not a qualifying advance.

## Selection and provenance

Actual start: syscoin/PVUGC PR #1, open/draft/unmerged, same-repository branch research/pq-wkem-validation-20260918 at 44ad7d5de4373071c8535e05ea7128823026b6fc. Read PR metadata, recent substantive discussion through R225, the exact head note SOURCE_SPECIAL_SOUNDNESS_TRANSFER_20261128.md (blob 3af9483ff912962140c24dcf9151ff9cead3c0af), and its paired-tree predecessor note at the same exact ref. Rechecked PR metadata at that head; this new path returned 404. No new Core claims, web research, agents or cryptographic checker execution.

Missing original operation: generate a public, witness-independent polynomial capsule from which each qualifying ORIGINAL certificate gives the same precommitted native cancellation contribution. Keep the full predicate V_x including all three OR grounds; no replacement by a toy predicate.

Selected change: use a conditional disclosure of secrets (CDS) on two complete local inputs, with a *whole-transcript claw* instead of transferable per-wire labels, paired terminal seeds, or a fixed challenge-response first message. The aim is to make the only key-producing equality certify the complete source relation. This removes the specific independently selectable wire-label interface of R289, if the proposed two sampler encodings can actually be realized. Test that realization and the closure of its *raw public output* before implementation. Do not assume the private CDS encoders remain private after publishing their descriptions.

## 1. Actual candidate equations

Suppose a deterministic polynomial Split maps each canonical original witness w to (u,v), and Join maps admitted pairs back to an original certificate. Include all claim/window/source context x in every invocation. Let R_x(u,v)=V_x(Join(u,v)), including format checks, for the proposed split. The public capsule is to contain descriptions of two classical PPT evaluators:

    (a,A) = Eval_L(C_L,u)
    (b,B) = Eval_R(C_R,v)

where a,b are whole-transcript labels and A,B are lambda-bit pads. Build samples a single k and E=sigma XOR KDF(ctx,k). For every qualifying w, the desired conditions are

    a = b,  A XOR B = k.

Open splits w, evaluates both descriptions, and returns E XOR KDF(ctx,A XOR B). A label-equality if-check in Open is not cryptographic protection: the adversary gets both A and B and can xor them without that check. A non-circular Build has to encode the same k across all accepted pairs while retaining full-public security against unrestricted calls to both evaluators and direct inspection of both encodings.

Unlike the previous fixed-transcript transfer, neither evaluator's label is frozen before w exists. An accepted claw is supposed to use the actual authenticated complete inputs, and every qualifying claw yields the same k. No assumption about being able to sample a qualifying w at Build. This is a proposed architecture only; derive the actual obligations on its realization next.

## 2. Closure of a raw two-message XOR disclosure

Regard the accepted pairs as edges in a bipartite graph on the actual canonical local inputs. Fix Build coins and hence C_L,C_R. If the pads are deterministic (or fix a public deterministic choice of evaluator coins), an edge (u,v) implies A(u) XOR B(v)=k. Along any length-two path u0-v0-u1,

    A(u0) = k XOR B(v0) = A(u1).

Similarly right pads are constant along a length-two path. By induction, for each nontrivial connected component there are constants r and r XOR k on its left and right vertices, respectively. The same path argument for the label equality forces one label value throughout that component. Thus every pair of opposite-side vertices of a component, whether or not it is an accepted edge, yields the raw key k and equal labels. There is no need to present the intermediate vertices or the path to Open.

The minimal length-three pattern has edges (u0,v0),(u1,v0),(u1,v1) and a missing edge (u0,v1). Directly,

    A(u0) XOR B(v1)
      = A(u0) XOR B(v0) XOR A(u1) XOR B(v0)
        XOR A(u1) XOR B(v1)
      = k XOR k XOR k = k.

This is a concrete structural condition on this candidate, not an assertion that such a pattern is efficiently obtainable on the actual Syscoin relation without an already-known original certificate. For security one would need to prove that arbitrary efficient selection of a left and right vertex in a common accepted component yields an ORIGINAL certificate or an independent hardness break. A valid certificate for one edge suffices to release the key anyway; the argument above does not give an adversary those edges. Nor does it imply a closure property for general nonlinear decoders or for a single evaluator depending jointly on both inputs.

A proposed repair is to split the relation by local validity predicates and an exact authenticated join label L:

    R_x(u,v) = Valid_L(x,u) AND Valid_R(x,v)
               AND (L_L(x,u)=L_R(x,v)).

This is a disjoint union of complete bipartite components, so the closure no longer enlarges the accepted relation *among locally valid inputs*. It is a genuine mathematical change from independent wire labels: the label must identify the entire cross-boundary compatibility class. It is conditional; no claim that the three original grounds admit this split with short locally verifiable inputs. Moreover the public evaluator must cryptographically enforce each local domain. Returning zero or refusing to output in ordinary public code is not that enforcement if the raw mask is computable elsewhere in the description.

## 3. Try implementing the repaired split using hash-only constrained trees

For a join label of N bits, let D_L and D_R denote the sets of labels realizable by locally valid inputs. The hoped-for implementation is to use a public encoding of a constrained hash PRF on D_L and another on D_R. It would evaluate pads from the label alone, with the two leaf values differing by k on the intersection, and local witnesses would only be needed to locate their respective labels. One might try ordinary GGM prefix-subtree seeds as the constrained keys and public per-subtree corrections. This is different from supplying local gate labels: a full shared label selects the whole leaf value at once.

There are two independent issues. First, ordinary GGM supplies pseudorandom leaves given a root, not two independently public root descriptions with a hidden common XOR offset at every shared leaf. Publishing k as an additive correction is not a construction. Second, even granting a perfect correlated-tree generator for free, the proposed *explicit prefix-cover* realization is already insecure in the hard-TRUE case.

Let the two descriptions expose polynomial lists of binary prefixes P_L and P_R and enough seed/correction data to evaluate at any extension of each prefix, as in ordinary subtree-key publication. Suppose their covered domains are exact. For every p in P_L and q in P_R, compare the first min(len(p),len(q)) bits. If they agree, set ell to the longer prefix followed by zeros to length N. This is an element of both domains, since one prefix extends the other. Conversely if the domains intersect, a common label extends some p and q, which must agree on their common prefix. Consequently the public scan finds a common label in time O(N |P_L| |P_R|) whenever the statement is TRUE under the proposed split.

Now evaluate the two published constrained keys at ell, obtain their two raw pads, xor them, and unmask E. This attacker uses only the serialized descriptions, not any local witness, adversarial representation, internal state, quantum rewinding, or oracle programming. It applies even if leaf correction correctness is perfect and even if each single-key marginal looks pseudorandom. It is classical PPT, hence also in the QPT threat model. If ell is itself a full certificate, the same scan efficiently finds an original witness and the assumed hard-TRUE case did not survive this representation. If ell is a digest or shorter join key, existence of local preimages is not a method for reconstructing them; the proposed construction already released without requiring them.

If the prefix covers overapproximate the actual domains, the scan may instead locate fabricated labels. Then either the correction identity extends there (unauthorized release) or a new cryptographic mechanism is needed to distinguish the actual locally valid inputs from the overapproximation. The argument is not a proof against arbitrary constrained PRFs, hidden access sets, non-XOR CDS, or hash-based WE generally. It specifically rejects public explicit cover keys whose raw outputs are available at extensions and whose common-domain equality supplies the key.

Trying to hash the full witness into ell does not fix the scan: it operates on the published label-domain descriptions rather than inverting the hash. Requiring the actual source preimage as a decryption input, instead of just ell, is the possible next change, but then the tree no longer implements the required evaluator. The missing algorithm is a public compiler of two preimage-dependent descriptions whose raw pads agree up to the hidden constant on every correctly joined pair, while remaining unavailable on fabricated local evidence. The setup cannot enumerate all future qualifying evidence to install one encrypted row per pair.

## 4. Decision and exact handoff

Reject the raw two-message XOR plus explicit constrained-prefix realization at preflight. Do not implement larger fixtures or replace the PRG. The graph closure determines where a local-domain/equality decomposition is even compatible with the raw output; the prefix-overlap scan rejects the concrete proposed polynomial public key representation even if the common leaf correlation is granted. Neither is a generic impossibility claim.

If retaining this architecture, the next actual operation is

    (C_L,C_R,k) <- JointBuild(x;rho)
    (ell_L,A) <- Eval_L(C_L,u)
    (ell_R,B) <- Eval_R(C_R,v)

where inputs u,v contain actual original authenticated local evidence, the raw outputs on every V_x(Join(u,v))=1 give A XOR B=k, and a public label alone does not suffice to compute either pad. JointBuild must be classical PPT and cannot depend on future witnesses or retain a source secret. A new candidate must specify how the source-preimage-dependent evaluation is encoded rather than just assume a CDS function whose local message algorithms remain secret. Alternatively abandon two-message XOR disclosure. The full-public simulator must jointly account for both descriptions, all raw outputs, E, native VK/message, context, maliciously retained source coins, auxiliary input, sibling capsules, selective openings and coherent hash access. Arbitrary recovery or accepted native forgery need not follow Eval_L/Eval_R or disclose a claw. No such construction or simulator is supplied here.

The source relation is unchanged: competing exact greater Bitcoin work, finite authenticated missing/invalid burn, qualified Syscoin incompatibility/tag fault. No source consensus or maturity assertion is added, no new endpoint/activation claim, and no change to N-of-N setup or same-capability requirement. The limited algebra above is not a full-public QPT proof. No ordinary PR comment or user notification.
