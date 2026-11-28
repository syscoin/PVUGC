# Fixed-transcript explanation as a source-to-native conversion — 2026-11-26

Research only; static candidate and repair iteration, not a release advance.

Continuity: actual PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, start and prewrite head 7dcfd3de85f7e7ba66fe282f77b48b9e548cf09e. Read latest substantive PR comments through R225, exact SOURCE_DUAL_COPY_RESOLUTION_ROUTING_20261126.md (blob 0a920bf5679ec23068945f3ae5549f237d2df664), SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md and SOURCE_PAIRED_INSTANCE_REDUCTION_20261126.md. New path absent at checked head (NOT_FOUND/HTTP 404). No new Core source claim.

## Selection before any implementation

Missing operation: classical offline Build must serialize one native cancellation contribution S such that any qualifying ORIGINAL BTC competing-work, burn refutation, or SYS inconsistency/tag-fault witness w opens the same contribution. Retain complete bounded R_x(w), including all actual authentication/relevance/maturity policies and native message/claim context. This note does not instantiate the original verifier. Closest proof-system regression: special soundness either extracts the wrong witness or needs a second opening of an independent setup commitment. Try a different mathematical operation: **explain the SAME already published accepting proof transcript with a new witness**, instead of answering a second challenge. Use recovered explanatory randomness as a candidate release channel. No local label splicing, new proof challenge or equality of separately generated proof strings is needed in the proposed interface. Test whether ordinary witness indistinguishability or honest-verifier simulation supplies this operation, and whether the explanation yields a common hidden value. If old independent-opening or public-copy attacks apply, reject before implementing.

## 1. Fixed-transcript explanation interface

For a public statement Q and two possible witnesses z0,z1, let P(Q,z;r) output a transcript T using explicit prover/simulation coins r. The proposed primitive is not a fresh proof generator. It would compute

    r' = Explain(Q,T,z1)
    P(Q,z1;r') = T

for a transcript fixed at Build. Build can know a native-mode witness z0=(1,S), whereas a future original opener knows z1=(0,w). For the illustrative relation use

    Q_x,y(t,z) = ((t=0) AND R_x(z))
                 OR ((t=1) AND H("native-check",ctx,z)=y).

Here y=H("native-check",ctx,S) is only a synthetic high-entropy capability check; the native signature and its joint checking-key distribution remain unproved. Build can always produce a proof using the second branch. Exact explanation is stronger than the ability to make a fresh proof, stronger than ordinary witness indistinguishability, and stronger than an accepting transcript simulator. The source-mode explanation must also lead to a native-mode secret, not just to coins appropriate to its own branch.

One concrete shell is Build choose r, form T=P(Q,z0;r), choose K=D(Q,z0,r,T), publish T and E=S XOR StreamH("explain-pad",ctx,K). Open computes r'=Explain(Q,T,z1), K'=D(Q,z1,r',T), then decrypts. This shell is not a constructed Explain or D. Completeness requires equality K'=K for every original source certificate (or a justified alternative construction yielding the same S); security requires joint hiddenness against arbitrary public algorithms, not just those asked to explain. A public D that uses only T immediately fails. This is not the special-soundness interface from the earlier note: the challenge and all public transcript bytes are unchanged.

## 2. Hash-commitment graph-proof candidate and exact support failure

Grant a standard public witness-preserving reduction to Hamiltonian cycle (HC), with a branch-tagged decoder. Consider the two-challenge graph protocol used in the earlier special-soundness note. For graph G with N vertices, permute by pi and commit independently to each adjacency bit a_ij using H("explain-adj",ctx,i,j,salt_ij,a_ij) with lambda-bit salts and injective encoding. Challenge 1 opens a Hamiltonian cycle in the committed graph. An ordinary challenge-1 simulator instead chooses a cycle L on N vertices, commits to the cycle-only graph A_L (all noncycle entries zero), and opens those cycle entries. For an undirected graph use a consistent symmetric adjacency representation; the argument is unchanged. Require G have strictly more edges than a cycle, which can be arranged in a synthetic yes-instance and is sufficient for this screen; do not claim every graph in the reduction has that property.

Try the following actual Build for the explanation strategy. Generate the simulated challenge-1 transcript T for the SOURCE graph using the above cycle-only simulator. Sample a setup salt u at a noncycle cell as part of that simulator's coins; use H("explain-pad",ctx,u) as the one-block payload pad (independent domains/expansion for longer payloads). Publish T,E. This is well-defined classical PPT even before a future source witness exists. The proposed opener with an actual source HC witness tries to explain the fixed T as a real challenge-1 transcript of G, recovering the hidden randomness, then derive the pad. No second challenge is required or supplied.

But a real first message commits to a permutation of G. Every permutation of G has more edges than A_L. For ANY purported full explanation (pi',salt'_ij), there is a cell with a'_ij != A_L,ij. In T that cell commitment has not changed, so the two complete openings give

    H("explain-adj",ctx,i,j,salt_ij,A_L,ij)
      = H("explain-adj",ctx,i,j,salt'_ij,a'_ij).

The input strings are distinct because their adjacency bits differ. A reduction that ran the simulator knows the original salts and can output this collision straight-line from any successful explanation. This is an exact implication using the actual fixed commitment bytes, independent of whether the transcript distributions are computationally indistinguishable. It applies to a QPT explanation algorithm with classical output; no rewinding or oracle programming is needed. Thus, if collision resistance holds, the proposed honest opener cannot generally provide such an explanation even with a genuine source witness. It is not a proof against all simulation methods or proof systems. This is an explanation-completeness failure, not an attack on the ordinary graph proof. Do not treat a simulated accepting transcript as an efficiently explainable transcript sampled from the real witness-conditioned prover.

Challenge 0 does not solve the release: its response reveals the full permutation and adjacency salts publicly. If S is masked using any such disclosed randomness, arbitrary public evaluation decrypts. Giving the source witness an ordinary proof of knowledge cannot change either of these cases.

## 3. Repair: generate a real transcript using the planted native witness

To avoid the cycle-only graph discrepancy, Build can use the full OR graph G_Q for Q and a genuine cycle C_S from the native branch. Sample pi_S and all salts, commit to A=pi_S(G_Q), and publish T=(D,L,opened cycle salts), where L=pi_S(C_S). For a future source cycle C_w, a real explanation of exactly this fixed T must contain pi_w such that pi_w(C_w)=L, along with openings of the same D. Absent commitment collisions the full committed matrix is the same:

    pi_w(G_Q) = pi_S(G_Q),
    alpha = pi_S^{-1} pi_w in Aut(G_Q),
    alpha(C_w) = C_S.

Cycles here are edge sets, or suitably canonically represented; equality of the labeled opened cycle is sufficient. This is the precise mathematical constraint on an alternate honest explanation, not merely a requirement to match a random proof string. The source witness lift only guarantees that C_w exists; it does not guarantee that it lies in the same automorphism orbit as C_S. In a reduction whose graph automorphisms preserve the decoded branch tag, this explanation is impossible for opposite tags. No such branch-invariance assumption is made for all HC reductions. In an encoding deliberately designed to put both branches in a common orbit, an actual efficient explanation algorithm still has to find a suitable labeling from the public committed view.

Grant that suitable labeling for free to inspect the remaining release. In the actual independent-salt construction, a full explanation additionally opens every cell, including cells outside L with independently chosen hidden salts. A differing salt opening yields a distinct-input hash collision; the real salt is independent of the source witness and even of the granted labeling. Exact recovery of one such salt in the ideal hash experiment with no correlated hint is the already recorded independent-opening obstruction. Reject this variant before implementation, not another oracle bound or fixture. Making every salt public lets the opener read A, but also makes any salt-derived payload pad public. A partial explanation containing only the permutation need not recover any hidden salt; the opened cycle salts were already public.

A different pad could depend on the hidden pi_S rather than a salt. Giving pi_S to the source opener would be sufficient to decode C_S=pi_S^{-1}(L) and S, but giving pi_S publicly lets any observer do it without the source. Even a successful alternate explanation pi_w decodes only pi_w^{-1}(L)=C_w. The relative automorphism alpha maps the source cycle to the native cycle, but computing alpha from pi_w and T alone is a new missing operation; neither the graph proof nor its commitment binding provides it. If alpha is disclosed in a way that does not require the source certificate, one still needs pi_w or C_w; whether a compact correlated disclosure enables this without revealing a native cycle unconditionally needs a separate actual construction and simulation. There is no claim that all graph-orbit transports fail. The precise next equation for this repair would be a public procedure producing a native-cycle-decoding transport from ANY original C_w, without revealing that native cycle by arbitrary capsule inspection. Standard witness indistinguishability only compares distributions; it does not supply this transport.

## 4. Handoff

The fixed-transcript explanation route is distinct from generating two special-soundness responses or independently choosing proof-search puzzles. It exposes two separate requirements: support/efficient explanation of the EXACT existing transcript, then recovery of the SAME hidden native capability from the new explanation. The cycle-only simulator fails the first by a direct collision implication. The real OR transcript gives an exact orbit constraint, and its full-tape version hits the previously known independent-opening obstruction. The partial orbit transport remains unconstructed. Do not retry the same independent salts, challenge repetitions, transcript padding, or local label fixtures. If pursuing explanation further, require an explicit hash-only compiler with witness-conditioned fixed-transcript explainability, and a nonpublic common extraction operation from the explanations, jointly simulated with the capsule. A proof system or deniable-transcript definition that simply assumes that last operation is not an independent foundation.

No source compiler, actual native capability, hard-TRUE arbitrary extraction, joint QPT simulator, malicious N-of-N setup or sibling-capsule proof. No change to R316 maturity correction or R225 slot-global/activation-specific endpoint scope. No code/checker or delegated agent executed; this static screen was sufficient to reject the tested repairs before implementation. No external literature, new Core inspection, or ordinary PR comment. Notification gate not met.
