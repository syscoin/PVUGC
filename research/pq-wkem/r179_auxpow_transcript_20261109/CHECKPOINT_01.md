# R179 — SHA/AuxPoW original-evidence key-release attempt, intermediate checkpoint

Status: **in-progress hypothesis only**, not a key-release construction or cryptographic breakthrough.

PR #1 branch `research/pq-wkem-validation-20260918`, actual starting head d08a082c0dbb68c1398a0d295724d907bd4267c8. R178 exact current research was read. It rules out public work-digest bucket pads, fixed public anchors and miner-issued private tickets; these are not repeated.

**Hypothesis:** a full byte-authenticated AuxPoW proof yields a source-dependent SHA/Merkle transcript and perhaps a stable secret transition that could be embedded directly in the encrypted cancellation capability. Test whether the transcript can derive the same frozen key for every valid fork witness without any public bypass, setup enumeration, independent work puzzle or source-secret issuer.

**Immediate experiment:** implement SHA256d parent header target, Bitcoin coinbase transaction Merkle binding, child hash chain-root binding, deterministic AuxPoW index, contextual Syscoin ancestor tag parser, source-history height and pair incompatibility. Use precisely tagged synthetic low-work fixtures; they do not certify BTC canonical chain inclusion. Then try an actual public hash-transcript release algorithm and raw-evaluate it on forged source values even when the honest source check rejects them. Preserve exact code and output. Full Bitcoin DAA, source state and canonical admission remain distinct.

The source predicate will bind the original withdrawal claim/UTXO and native challenge message, tag scope, BTC anchors/window, actual child outcome rather than distinct parent WorkIDs, and protocol fork-depth requirement. A valid source checker is an indispensable component but **is not a WE gate**. A common secret must come from the original evidence cryptographically, not from an honest `if` in Open.

No lattices, public groups, external literature, online committee, native signer claim, proof of QPT security or elapsed-work estimate. No checker has yet been executed for this candidate.