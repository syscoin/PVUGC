# R231 — Preselected hash rows and future-source release

**Nonconstructive research-only hash candidate; not a witness-KEM, native signature construction, SHA theorem or QPT proof.**

## Continuity and provenance

syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918. Starting SHA 69b059fed9488a1e55bccba79f185d95c94989f1. Exact R230 research blob read 0985353843e042e776f69e1ea22531408e9f5e19; R229 public-source-finder note read. Intermediate checkpoint 358d3f000b5a83731a3e27c0d4af440c36019a04 published BEFORE experiments. No outside web, literature, full PR diff, production changes, agents or quantum tests.

checker.py was executed twice locally with byte-identical captured.json and rerun.json. SHA256 checker 2b1a5a98ea366ac0cb699ff0a60567d1ae1447f335448b68654f33824aaf5105; Git blob ac7f30a4a66cc5165791850d622079de13cb4f56. SHA256 captured 21368a1c02a6fcb38901f96b5b895836f1d272fc0c95a4ef3078e0a33de27a97; Git blob d69637c81ea071f178eeecedbf905bfdc0035541. Local full research draft SHA256 25082c04030f73a8d39a211aa65e03e4a81fa0421a995a3b0000a741350b6106, not identical to the present published derivation. 4,662 toy functional assertions do NOT establish native/consensus/QPT security.

## Original three-way bridge relation

Fix claim x = precise vault outpoint, withdrawal amount and recipient, native cancel message/VK, earlier N-of-N preauthorized graph, later one-notary activation and authenticated BTC/SYS history commitments, source windows/anchors and relevant data availability. A permissionless challenge succeeds with any ONE of:
(1) qualified, contradictory BTC history with strictly greater cumulative target-derived work;
(2) exact authorized burn absent or invalid in the bound qualified Syscoin state with finite authenticated nonmembership/refutation;
(3) qualified Syscoin ancestor/fork inconsistency with required LC depth or a separately admitted authenticated tag fault.
Distinct parent work proofs for the same pure child are not a fork; qualifying fork contradiction need not select a winner. A random mined hash, missing transaction lookup or fabricated tag is never qualified. One-of-N initiation and N-of-N preauthorization are separate; BTC receives only native cancellation authorization.

## Named attempted construction

Freeze a precommitted signature or secret capability sigma before future source proof W. Candidate public capsule has D = sigma XOR P where Build fixes P before W exists. Public Open computes

    Open(D,W) = D XOR H_pad(Z_x(W)).

Every ORIGINAL valid W must satisfy H_pad(Z_x(W)) = P for the SAME sigma. With unrelated future SHA work/child outputs this equality fails (scoped direct-pad-family issue, not generic hash-WE impossibility). R230 already tested raw work hash mismatch and public difficulty-prefix leakage; those tests are not relabeled as progress here.

### Precise future-entropy identity

If future source W is sampled with Markov condition sigma -> (C,x) -> W, then

    I(sigma; C,W | x)
      = I(sigma;C | x)+I(sigma;W | C,x)
      = I(sigma;C | x).

An independent public source event cannot add new Shannon information to an independently one-time-padded capsule. This DOES NOT exclude computational WE, where C can contain the secret information-theoretically but require a witness for *efficient* extraction; the missing object is that computational source-conditioned encoding. If a malicious source retains setup secrets, this Markov premise may fail, creating another security obligation.

The checker exhaustively verifies that after observing every 4-bit public C and independent W, each 4-bit native K remains equally possible under C=K XOR S with uniform S: 4,096 conditional-frequency checks and 256 posterior-size checks. This is toy algebra, not crypto security testing.

### Multi-row hash-table repair

Let setup preselect q future source labels w_j and publish rows

    D_j = sigma XOR H_pad(w_j).

If w_j are public to enable public Open, an attacker can decrypt from any row WITHOUT an authenticated ORIGINAL witness. If w_j are hidden/committed, future unrelated W must hit one of q preselected labels; for independent uniform N-point source distribution the exact coverage is at most q/N. A polynomial table cannot automatically cover every future unknown high-entropy eligible source proof. This is not a universal impossibility theorem.

The checker uses N=65536 and q in {1,2,8,32,256}, verifies exact coverage q/N, and confirms all 299 rows with public SHA256-domain-separated labels leak the same synthetic sigma before a source event. The source values are strings, NOT qualified Bitcoin/Syscoin evidence.

### Three repair trials

1. Pad with common digest prefix imposed by target: the prefix is public from target, so sigma = D XOR H_pad(public_prefix) leaks immediately; a low digest is not an authenticated source proof.
2. Pad with hash of a fully authenticated Merkle proof's final root: both valid paths normalize to the fixed public root. Anyone can compute that pad without presenting a proof. Fixture computes actual SHA256 Merkle nodes for four synthetic leaves, but no production state.
3. Use secret setup salt s and H(s,W): if s withheld, public Open cannot compute; if disclosed, the raw keyed computation can bypass an honest-only source validator. H(s) does not implement a secret-to-original-source transfer. A purported constrained hash key for digest<T likewise admits fabricated digest values until *source authentication is cryptographically inside raw opening*, not only a public if-check.

Nothing here supplies the needed all-witness correlation from actual SHA/AuxPoW. Source actors may generate private work and retain labels; false, hard-TRUE, related-capsule and quantum joint attacks cannot be dismissed by hashes alone.

## Missing algorithm

Required classical PPT Build_hash(R_original,x,sigma) -> (C,CK,aux), and public Open_hash(C,w) -> the SAME sigma for EVERY qualifying original certificate. In the full public quantum game, arbitrary unauthorized final-key recovery or accepted native signature forgery must yield an ACTUAL qualifying source witness or independently justified QPT hash/native break, without requiring a trace or supplied representation. The proof must cover malicious setup/source correlation, arbitrary related capsules/auxiliary inputs, source work membership, and native claim/path confinement. Neither this fixture nor the published note constructs that. A genuinely different non-direct-pad source-conditioned release mechanism is the next milestone. No PR progress comment warranted.
