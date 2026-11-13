# R260 — hash-only source-signature release and equivocation repair (NONQUALIFYING)

This is **not** an ORIGINAL BTC/Syscoin bridge WKEM, QPT security proof, native PQ deployment design, or claim of a practical solution. It is a concrete construction/repair experiment testing whether actual hash-based one-time-signature secret revelations can provide the source-conditioned input delivery missing in R247–R251. Neither attempt can be embedded in the ORIGINAL bridge without changing the trust and evidence model.

## Pinned continuity and scope

Read PVUGC PR #1 at start head e124033b67315ee1d17e1988f3ff1a91cdf6952b, branch research/pq-wkem-validation-20260918; read R259 RESEARCH.md blob 742748dc45c59e6ebb99b978fdb1c7601e97fbb9. Core #609 metadata was read-only at head c91539de3c34937e57d7f5fda47c7b0502ff33f6; no current Core source read, Core test run or consensus audit in this iteration. No new top-level PVUGC PR comment since 2026-11-12 00:00 UTC was observed.

The unchanged ORIGINAL relation includes an independently source-admitted BTC higher-work competing branch, finite claim-bound burn/authorization fault, or authenticated Syscoin claim-prefix canonical AuxPoW inconsistency / separately qualified source-assertion tag fault. One notary initiates; any qualified observer challenges; no later online release signers; ChainLocks optional. The supplied canonical post-PQ rule permits at most one valid modern Syscoin child per authenticated parent commitment, not one child for all parents. A genuine fork does NOT automatically entail double-signing by any source signer.

## A. Every valid Lamport source signature releases the same K

Choose independent secret 256-bit preimages s[i,b] for every digest-bit index i and b in {0,1}; publish pk[i,b]=SHA256("public"||s[i,b]). Let K be a frozen cancellation key, choose uniform xor shares S[i] with XOR_i S[i]=K, and let a builder knowing all preimages publish

    C[i,b] = S[i] XOR SHA256("pad"||s[i,b]).

A Lamport signature of message m reveals one s[i,b_i(m)] for each i. A public Open XORs C[i,b_i(m)] XOR SHA256("pad"||s[i,b_i(m)]) and obtains exactly K, for every message with a valid Lamport signature. This is a real hash-and-XOR common-key correctness identity in the SYNTHETIC signed-message relation. No canonical message or future-witness enumeration is needed.

But the decrypted shares are available for **any** Lamport-signed message, not necessarily an ORIGINAL authenticated BTC/Syscoin source challenge. A local CheckSource predicate applied after this raw decryption cannot protect K. Worse, the signing-key holder and builder that know both preimages can recover K **before** any source event; honest preauthorizer erasure does not stop a different malicious source signer who retains its signing key. If the preauthorizer only knows actual Syscoin sentry public keys, it does not know preimages needed to compute these C rows. A new signer restricted to source-challenge statements becomes the prohibited online release authority. This is not a secret-opening interface already supplied by SHA256d/AuxPoW.

## B. Repair attempt: release only from two different OTS messages

Use the same Lamport signing preimages, but publish for each i

    E[i] = K XOR SHA256("dual-pad"||s[i,0]||s[i,1]).

Two signatures under the **same one-time Lamport key** on messages with DIFFERENT digest bitstrings reveal both secrets at some index i. Their holder computes the pad and recovers the identical K from E[i]. A single signature reveals only one preimage per index; that direct dual-row method cannot open. Different messages with equal digests are not covered except under a collision-resistance qualification. This deterministic two-signature correctness is verified in the finite model, but is **not** arbitrary QPT security.

The repair still fails ORIGINAL source security/completeness:

1. Two unrelated signed messages reveal K, with no authenticated BTC/Syscoin source conflict; a post-hoc validator cannot prevent raw E[i] evaluation.
2. The signer/builder holding s[i,0] and s[i,1] can recover K at setup without ANY message or source certificate.
3. Actual post-PQ ChainLock signers use scheduled Merkle-WOTS+ leaves, not synthetic Lamport pairs; two WOTS+ signatures need not disclose both of these imagined independent secrets. No compatibility proof.
4. The ORIGINAL fork/tag inconsistency can occur without ChainLock signer equivocation at all; requiring two same-OTS signatures changes the accepted challenge relation and loses every-witness completeness.
5. Preexisting source public verification keys alone do not give the pre-funding builder the hidden s preimages required for E[i]. An actual public-key encryption-to-unknown-signature-preimage compiler, source-signer setup participation, or a new trusted online service would be needed. None is supplied by this experiment.
6. Canonical AuxPoW one-parent/one-child binding does not imply cross-parent OTS reuse. The native R225 fixed-sighash cross-activation problem is untouched.

## Exact structural lesson

The original admissible source evidence is a valid, fully authenticated chain/history **of publicly computable hashes and coinbase tags**; it does not inherently reveal a private opening seed precommitted by the N-of-N builder. In the synthetic OTS constructions, that hidden seed is supplied by a separate signer, and this signer can recover cancellation authority early. Merely substituting valid source SHA or a public source-checking predicate for the signing secret does not supply input delivery. The missing equation remains actual classical-PPT Build_inc(x_W,sigma_cancel), public Open_inc(C,w)=the SAME precommitted safe cancellation authorization for EVERY independently admitted original challenge, and a FULL-public arbitrary-QPT unauthorized recovery/native forgery -> ACTUAL original certificate or independent justified hash/native break, with malicious setup and sibling capsules.

The only positive fact established is exact common-value correctness in an independently specified **synthetic Lamport-signature relation**. That does not materially reduce the ORIGINAL bridge-source obligation; no qualifying milestone or PR comment is warranted. It is not an impossibility theorem for hash-only source-specific WE.

## Executed finite reproduction

Two local Python SHA256 checkers were each run twice with byte-identical output. checker.py: 32 synthetic keys, 32 qualified-message openings, 32 unrelated-message openings, 32 builder pre-evidence recoveries, 32 unrelated-message raw-check bypasses (128 test groups). check_two.py: 32 synthetic keys, 32 different-digest signature-pair recoveries, 32 unrelated-signature-pair recoveries, 32 signer pre-evidence recoveries, 32 same-message no-dual-row checks. All keys and messages are deterministic toy fixtures; no genuine Bitcoin/Syscoin source verification, real WOTS+, native PQ Bitcoin signature, honest distributed ceremony or quantum attack/testing occurred.

SHA256 of exact local executable scripts/output:
- checker.py: 63d9778fb6ce6d1d1d3458bdaa35bfb574bc4159e9a1acceb64d810f69e8514a
- result.json: 204851752d3d773242325144b5b0e3b45673e7809bb7bcf143a6e2e4215ec20b
- check_two.py: 50a709ae55fab8ebaa8fd74733b90043a72208eb7e922b6a9205f56a24925930
- result_two.json: c5b4b7e93b7138e72783d5151ab68e25f3f3fe1a7d730e6c490104cd5d5aaefb

Full local derivation/checkers/results are independently archived for this run; this GitHub note is the research checkpoint. The checker hashes are provenance, not a claim that code was published to this branch. No other repository writes are authorized or implied.
