# R391 — Frozen N-of-N activation signature with future assertion binding (NONQUALIFYING)

## Continuity
PVUGC PR #1 was read at 9f1f053736d781773763475fcd513e0684ee9388 on research/pq-wkem-validation-20260918. R390 note blob a903d41f09899d2e01e80039d4534db7fb0de384 and R389 note blob 0c6bd14c514d0188f6a0a3c261f6e553642548d5 were read. Recent top-level comments since November 18 were empty. R389's original-source-dependent hash edge seal remains missing. This pass addresses a different, essential endpoint circularity, not another source-pad/hash-mask variant: can frozen setup signatures authorize future claim-bound activations WITHOUT an online N-of-N round?

## Concrete native operation
At ceremony freeze vault input u, its amount V and scriptCode, version, sequence, locktime, and a protected full-value output O0=(V, fixed claim-INDEPENDENT staging script). Each setup participant pre-signs input0 with SegWit-v0 SIGHASH_SINGLE|ANYONECANPAY, type 0x83. BIP143 computes:

    h_pre = SHA256d(version || zero32 || zero32 || outpoint(u)
          || varbytes(vault_script) || uint64LE(V) || sequence(u)
          || SHA256d(serialize(O0)) || locktime || uint32LE(0x83)).

This is unchanged by subsequently appending an independent fee input, outputs beyond index0, and a canonical OP_RETURN assertion commitment as output1. The live authorized notary separately signs input0 with SIGHASH_ALL; the vault script must require that notary as well as all frozen N-of-N signatures and have no bypass. The notary pays fees using its separate input and O0 receives the entire V, so adding an output does not transfer vault value. Changing O0 amount or script invalidates the frozen signatures.

For a future claim x the activation A_x has nonwitness output1 containing OP_RETURN("SYSWC" || SHA256(canonical claim)). Distinct claims have distinct txid(A_x) under hash binding. The future cancellation spends (txid(A_x),0), so a subsequent native SIGHASH_ALL signature for one activation is not portable to a different activation's outpoint. This repairs one narrow R225 common-outpoint portability case CONDITIONALLY on a genuine protected signer. The claim is NOT part of the already frozen N-of-N signature.

## Executed bounded checker
Actually executed a Python 3.13.5/cryptography 46.0.4 checker twice, obtaining byte-identical results. It implemented BIP143 digest construction and real secp256k1 deterministic ECDSA signing with two PUBLIC fixture setup keys and one live notary. Frozen 0x83 signatures verified across changed claims, extra outputs and added/removed fee inputs, but not changed protected O0 value/script. The notary SIGHASH_ALL signature was claim-specific. Different claim outputs produced different activation txids and different future cancellation sighashes, and cancellation signatures on A did not verify on B. The full vault amount reached O0; fees came from an independent input. These are synthetic fixtures, NOT Bitcoin VM/chain admission, Core, original AuxPoW witnesses, FE, ZK or quantum tests.

The checker deliberately constructed malformed assertion output1 that left the frozen 0x83 signatures fully valid. Thus the script does NOT guarantee that the assertion is canonical; source authorization must be cryptographically enforced elsewhere. Malformed/omitted claim handling must be explicitly certified as an approved finite invalid-burn-authorization fault or the actual graph must prevent unsafe settlement. Neither is proved here.

Exact local files: check.py SHA256 3d6f39297444a06101e75fd30a8c942fb6dc51347bb650974b3abdc8eca31a29, each output SHA256 738856df446b29a61088f87329446db2bbf4dec9c10e651be0fd94acbebe13f7, full RESEARCH.md SHA256 667d459e79357ed7d48cf156c9afd44e8835ba70ed4474d23e0cee83d189b2ca. Local archive R391_activation_presign_endpoint_20261119.tar.gz SHA256 d1190217132d1ec056d7380c81daae79b9c64a8db85d5e19136dd8f9f30c2a20. Checker/output are LOCAL-only and are NOT represented as GitHub-published bytes. Fixture keys are PUBLIC and must never protect funds.

## Unresolved ORIGINAL source release AND payout graph
The claim-independent staging output does not restrict an unknown later withdrawal payout recipient/amount. A retained notary spending key could otherwise steal after timeout. A complete covenant-emulation graph must enforce the claim-specific payout and cancellation, with no honest-key bypass, malformed-claim safety, exact native sighash/VK/message/anchor/session binding, and complete data before funding. No such graph was constructed.

Because initial N-of-N ceremony can precede unknown future claims, fixed x_W / fixed-sigma witness encryption is not enough. The stronger actual capsule would need to be a restricted DYNAMIC signer compiled at setup, checking source evidence INSIDE protected evaluation:

    C_i = Compile_R(sk_i, vault_session, policy;rho_i)
    Open_i(C_i,A_x,claim,T,w) = Sign_i(NativeSighash(T))

ONLY if A_x is the exact authenticated activation; T is the safe, correctly claim/outpoint-bound cancellation; and w satisfies the ORIGINAL three-branch relation for that claim: strictly more exact competing Bitcoin chainwork; finite authenticated invalid specific burn; OR qualified relevant Syscoin history inconsistency or tag fault at LC depth with the activated strict modern AuxPoW contextual rules. It must return a signature, NEVER the unrestricted private key.

No classical-PPT serialized hash-only source-conditioned Compile/Open, full-public FALSE/hard-TRUE QPT extraction, malicious-setup/sibling/auxiliary security theorem, or proof of source work was constructed. Dynamic signing is harder than fixed-signature release, and this endpoint does not substitute for the missing FE/WKEM foundation. No original source verifier, native full graph or qualified witness was run.

**NONQUALIFYING**. A specific safe signature-template invariant was established at the native digest/signature level; ORIGINAL source release remains missing. No progress comment, user breakthrough notification, production/Core edit, deployment, transfer or automation change.