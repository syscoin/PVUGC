# Hash-authenticated opposite-branch preimage carrier — intermediate checkpoint

**Scope:** This is a hash-only, source-authentication-key-carrying *restricted* candidate, NOT a generic ORIGINAL witness-KEM and not a source validity compiler. No solution, user-facing breakthrough, lattice, public group, online release authority, or Bitcoin NP verifier is claimed.

## Polynomial-time candidate
For a setup-controlled two-outcome 0/1 hash-preimage attestation, Build chooses independent 256-bit a,b, fixes K=a XOR b and freezes sigma. Publish vk0=SHA256(D0||a), vk1=SHA256(D1||b), CK=SHA256(DK||K) and Dsig=sigma XOR SHAKE256(DM||K); use unambiguous, independent, context-separated inputs. If the future evidence contains BOTH a and b, Open checks each respective public preimage commitment, reconstructs K, checks CK and releases the SAME sigma. Different valid certificates may be distinct but must disclose those same signed tokens to satisfy this restricted construction. Build/Open are explicit classical PPT with no post-hoc source-verifier oracle.

**Straight-line extraction for the restricted transcript:** Given a valid branch-0 disclosure a and the exact final K output by ANY key-recovery algorithm (even QPT), compute b=a XOR K, which is a preimage of vk1. This does not prove QPT secrecy in the full jointly correlated public view; the inverse simulation with the challenge hash and all auxiliary data is not supplied. A native accepted signature may also require a separate native forgery reduction.

## Actual check before writing this note
An actually executed SHA256/Shake256 Python standard-library checker produced byte-identical output over two runs. 64 deterministic fixtures successfully opened with both branch tokens; wrong tokens were rejected. A deliberately invalid anchored source header still caused the raw cryptographic Open to release sigma when a,b were supplied: original-source binding FAILS. No real Bitcoin/Syscoin evidence or QPT test.

## Constructive repair attempt
Make source validity intrinsic by binding the pads to the future authenticated WorkID; but if WorkID is unpredictable before Build, a prechosen K cannot equal the hash of ALL distinct future WorkIDs without an additional correlation mechanism. The signer who retains BOTH OTS preimages knows K ahead of source publication. An honest eraser who deletes them cannot produce subsequent dual attestations. Requiring a signer to certify actual chain inclusion at event time would be an online source authority, not the requested hash/PoW compiler. A public R_ORIGINAL check after Open does not stop direct token XOR.

Actual ORIGINAL witness still requires headers, AuxPoW parent, coinbase tags, ancestor/window/height, source snapshots and canonicality. OutcomeID names child semantic claim; WorkID names a complete work certificate, and two parent proofs for one child are not an incompatible source fork. No generic-NP solution, malicious N-of-N source security, honest-erasure protocol, arbitrary final-key recovery-to-ORIGINAL witness, or full-public QPT theorem.
