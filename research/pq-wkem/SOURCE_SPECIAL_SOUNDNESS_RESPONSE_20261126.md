# Special-soundness response conversion trial — 2026-11-26 UTC

Status: nonqualifying construction/repair iteration. No original release mechanism or full-public security theorem.

Continuity: PVUGC PR #1 open/draft/unmerged; start head 467d99595919ba1525fcc4fa3074595e38eb5fa6, branch research/pq-wkem-validation-20260918. Read actual PR metadata, latest five substantive comments through R225, latest commit filename, and exact SOURCE_LATE_BOUND_MERKLE_ROOT_GARBLING_20261126.md, blob 465a29d783f4b44657a15bac3a904f668e2f5757. Re-read head before preservation; new path returned NOT_FOUND / HTTP 404. No new Core source or deployment claims.

## Selection before construction

Missing operation: offline classical Build must serialize a public conversion that maps EVERY qualifying future original BTC/SYS/burn certificate to the identical frozen native cancellation contribution S, not merely to a valid source proof. The closest relevant attacks are R289 label splicing and the immediately preceding late-root label transfer attack. A genuinely different proposed mechanism is public special-soundness extraction from TWO responses to one globally binding first message, rather than local independently released wire labels or a transferable root-rekey secret. This would enforce consistency of the two complete responses by hash binding. Test whether the extraction can be made to return the native contribution instead of the source witness, and whether a future original witness can create the required second response without knowing the native contribution. Neither is assumed.

Retain all three original OR branches and their complete authenticated admission and relevance policies as a bounded relation R(x,w). Here x includes the full claim/context and native-message binding. No new relation or weakened source policy is proposed. A circuit-to-Hamiltonian-cycle encoding is used as a local illustrative proof-system implementation; grant a polynomial witness-preserving encoding with public cycle encoder and decoder. This is not an implemented source circuit or a new primitive assumption that releases S.

## 1. Try publishing one fixed special-soundness transcript

Let y be a public hash commitment to S with injective context encoding, and use the OR circuit

    Q_x,y(t,z) = (t=0 AND R(x,z))
                 OR (t=1 AND H("native-check",ctx,z)=y).

Build can sample S as a synthetic high-entropy capability for this trial, or take S as input. A real native VK and exact message would need the actual joint security argument, not this synthetic check. Let G be the public graph representing Q, and C_S a Hamiltonian cycle encoded from (1,S). The decoder must output a branch-tagged witness for any accepted cycle. The same cycle cannot decode to two different branch tags. For every original witness w, the encoding produces a cycle C_w with decoder output (0,w) (or a valid equivalent source witness, still with tag 0). The graph description alone is not assumed to hide y or S beyond any actual justified primitive.

Consider the standard two-challenge graph proof: for a permutation pi of the vertex set, commit to every adjacency bit a_ij of pi(G) with independent lambda-bit salt u_ij:

    D_ij = H("adj-commit",ctx,i,j,u_ij,a_ij).

Use injective, domain-separated encodings. Challenge 0 response A0 contains pi and ALL bits/salts, so a verifier checks the complete permuted graph. Challenge 1 response A1 contains an ordered Hamiltonian cycle of permuted vertices and the salts opening its cycle edges to 1. With two accepted responses for the same D, absent a hash collision the edge bits opened in A1 agree with the complete matrix in A0. Extract the original cycle pi^{-1}(cycle(A1)), then decode. The proof binds one complete graph and cycle; cross-response mixing at a matrix position cannot invent an edge without violating binding. This avoids the particular local-label splice at the level of proof verification, not yet at the level of secret release.

Orientation A — Build publishes D,A0. This is actual classical polynomial public data; every future original w CAN make A1 using pi(C_w) and the published salts. Exact extraction, however, gives Dec(C_w), the source branch. It does not give (1,S). Publishing a genuine source-response generator therefore solves the response-availability half, but not the capability-conversion half. This is true even if binding is perfect and extraction is a deterministic public algorithm, so no classical rewinding or QPT extractor assumption would repair the wrong extracted value.

Try the actual extra ciphertext

    P = S XOR H("cycle-pad",ctx,enc(C_S))
    Open(D,A0,P,w) = P XOR H("cycle-pad",ctx,enc(C_w)).

For variable-size S use an independent domain-separated hash stream of the needed length; the following argument concerns one lambda-bit block. Fix valid disjoint tagged cycle encodings, independently of this pad domain. Correctness holds exactly when the two pads agree. Since C_S != C_w, ideal-oracle agreement probability for the block is 2^-lambda. The result is not improved by verifying A1 first. This fails completeness even before adversarial evaluation. Publishing a separate correction for each cycle would require Build to know/enumerate those future original witnesses. A correction callable on all cycles, including invalid ones, is not acceptable merely because honest Open verifies first.

A public graph encoding with C_S = C_w is impossible with the stipulated deterministic branch-tagged decoder. Removing the branch tag is not a repair by itself: extraction must then yield S from every source-generated cycle. That changes the graph encoding into the missing source-to-common-native-value converter; standard NP reduction supplies no such property.

Orientation B — Build instead publishes D,A1_S for pi(C_S). The extractor WOULD give (1,S) if the future opener could produce A0. This reverses the bottleneck. It must open every commitment of the precise fixed D to pi(G), not generate another first message with its own independently chosen pi or salts. Producing a proof about a fresh D' does not permit this extraction. A public verifier check accepting D' would be a change to the extraction premise.

## 2. Explicit attempt to make orientation B publicly evaluable

Grant the opener pi, G, the exact permuted adjacency matrix, every salt except one u at a cell not opened in A1_S, and a fully qualifying original w independent of that salt. This is more information than the unmodified candidate supplies. Use graphs with at least four vertices so a cycle leaves unopened matrix entries. The remaining response operation is

    given h = H("adj-commit",ctx,i,j,u,a), a, w,
    output the exact u or another valid opening.

The salt u was sampled independently in Build. No element of the original certificate authenticates or reveals this independently generated salt. In the ideal hash model choose u uniform in N=2^lambda, h uniform, and program the single domain-specific point (ctx,i,j,u,a) to h in an otherwise random oracle O. Conditional on u this is exactly the real distribution for this commitment. All other given salts and commitments may be generated from their distinct cell domains; their full distribution is independent of the target point and its programming. This is a joint generation for the stated experiment, not a claim about arbitrary additional correlated hints.

In the baseline with no programming, the target u is independent of the view and oracle, so exact u recovery is at most 1/N. For an arbitrary q-query quantum algorithm, at each baseline query the expected probability mass at the programmed address is <=1/N (even when query states depend on h and other disclosed data). Replacing the oracle queries one at a time with baseline prefix and programmed suffix gives mean final vector norm distance <=2q/sqrt(N). The success-probability difference is bounded by the same quantity. Thus exact u recovery <=1/N+2q/sqrt(N) in this idealized experiment. For classical honest evaluation the analogous first-hit bound is (q+1)/N. A different opening is not an exact-recovery event; it gives distinct inputs with equal hash output, and must be handled separately as a collision event. No preimage/collision hardness claim about concrete SHA follows automatically.

The proposed second-response operation is therefore not a usable classical PPT algorithm under this independent-salt design, even for an opener already possessing a genuine certificate. This is a correctness obstruction, not an attack on actual deployed proof systems. In particular, using a witness-generated proof of knowledge of w, Fiat-Shamir, or a succinct proof of R(x,w) does not produce this old commitment salt.

Try generating u as H("source-salt",ctx,w) instead. Build cannot select that value before arbitrary future original w exists. For multiple qualifying w, those domain-separated inputs generally produce different salts, and one fixed D cannot bind all those openings without hash collisions. Making u public makes the second response possible for everyone (with pi and the other openings), and then extraction of A1_S is unrestricted. Publishing the unknown salt masked under a source-dependent pad is precisely the original unimplemented release operation. These repairs are rejected without larger test fixtures.

## 3. Try changing the extractor, rather than the salt

A further proposed route was a public normalization N_G(C) of graph cycles, used instead of raw enc(C) in Orientation A, with

    K = N_G(C_S) = N_G(C_w) for every qualifying w,
    P = S XOR H("normalized-cycle-pad",ctx,K).

This would solve the same-value issue IF N_G were actually constructed and K remained hidden from a public adversary without a qualifying original witness or independent break. The ordinary Hamiltonian-cycle invariants (vertex set, length, parity of the induced cyclic permutation) are common but computable without any cycle, so they directly reveal the pad. Hashing the ordered edge list is not common. A public normalizer that preserves branch tags cannot map native and source cycles to identical tagged normal forms. Erasing the branch tag alone does not normalize their different witness-dependent edge patterns. No independently justified hash-only normalizer with the required hidden common value was found. This is not a proof that all graph encodings or rewrite systems fail; it identifies the exact missing operation for this particular attempted proof-system conversion.

One can also change Q to an AND relation requiring both w and S. Then special soundness can extract both, but the ordinary cycle encoder requires both to construct the challenge-1 response; source-only completeness has simply been removed. An actual source-only cycle encoder for the AND relation would already be a public release algorithm after decoding, and cannot be granted as part of a standard reduction.

## 4. Handoff

The original relation has not been weakened. The proof-system conversion is distinct from the prior low-degree/private-coefficient, DPF-terminal, and late-root garbling trials. It permits a globally binding first message and honest arbitrary-source response in Orientation A but extracts the wrong witness; Orientation B extracts the right witness but the fixed setup-dependent response cannot be constructed by the future source holder. Do not repeat by changing the hash commitment domain, repeating the challenge, replacing the graph proof with an ordinary MPC-in-the-head or Fiat-Shamir proof, or granting a trapdoor response generator without implementing it. The next useful change would have to construct a response conversion whose setup commitment can be reused by every original witness, and whose deterministic extraction is the frozen native contribution rather than the original witness alone. A public proof of source correctness does not itself implement that conversion.

No claimed independent-QPT full-public reduction, no original source compiler, no real native signature or checking-key correlation, no arbitrary hard-TRUE extraction, no related-capsule or malicious distributed setup proof. No changes to R316 maturity correction or R225 endpoint scope. No external literature, Core reinspection, code execution, checker, delegated agents, ordinary PR comment or production action. The notification gate is not met.
