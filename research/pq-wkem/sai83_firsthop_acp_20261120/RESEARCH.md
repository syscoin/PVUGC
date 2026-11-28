# SAI-83 — offline first-hop claim binding with pre-signed SIGHASH_SINGLE|ANYONECANPAY (ENDPOINT COMPONENT, NONQUALIFYING)

## Source and intent

On 2026-11-20 this iteration began at open draft syscoin/PVUGC#1 branch research/pq-wkem-validation-20260918, SHA 2fdd0f1148ca6734f81d95c5af2c210ceb21167f. Current NCBP and preceding OPT-VK notes were read; latest ordinary comments since 2026-11-18 were absent. No other repo or Core code was written. The preceding research's public state/branch-product families remain insecure and are NOT resumed here.

The prior FE assessment proposed putting H(claim) in the activation transaction's nonwitness output, so the activation txid and subsequent cancel outpoint bind a later assertion. The missing native step is how N setup participants can preauthorize an UNKNOWN future claim while never responding again. A SIGHASH_ALL pre-signature would change with that claim output. This note supplies a specific FIRST-HOP native signing template—not the missing FE source-conditioned cancel gate.

## Classical construction

Let input 0 spend a known funded vault outpoint U holding M sats. The approved U P2WSH script requires N independent setup keys AND one authorized initiating notary signature, with no alternate bypass. The only protected output is fixed E=(M,ScriptEscrow), placed at output index 0. Before funding, each setup participant verifies U's entire script/graph and makes a valid native ECDSA signature over BIP143 input 0 using sighash byte 0x83 = SIGHASH_SINGLE|SIGHASH_ANYONECANPAY, with exact amount M and scriptCode Q.

The signed digest is

    SHA256d(nVersion || zero32 || zero32 ||
      outpoint(U) || CompactSize(len(Q)) || Q ||
      uint64LE(M) || nSequence(U) ||
      SHA256d(serialize(E)) || nLockTime || uint32LE(0x83)) .

Thus N signatures bind the vault input and the ENTIRE paired E output, but not other inputs or outputs. At initiation, ONE authorized notary chooses W, adds a second fee-paying input and optional change, and appends a zero-value OP_RETURN PUSH32 SHA256(W) as output 1. The notary signs the finalized activation input using SIGHASH_ALL. The N pre-signatures remain valid; the notary signature binds the actual claim output. The fee and any extra change must be supplied by other input(s); E retains the entire M sats. The source input/output pairing rule must be respected under input reordering.

Different W lead to different nonwitness activation txids, so cancellation spends distinct u_W=(txid(A_W),0). A genuine SIGHASH_ALL cancellation signature for W0 cannot be reused for W1 without a native-signature forgery/commitment failure. This fixes the specific portability across claim DIFFERENT activation outpoints, not a common fixed outpoint.

### Conditional one-honest first-hop safety lemma

Assume native witness-v0 script and hash verification are correct, at least one setup signer h is honest, every U-spend must contain h's signature, h exposes only the approved 0x83 pre-signature and protects/erases other signing secrets, and the source graph has no alternate spend path. Every accepted U-spend using h's pre-signature must have the byte-identical protected output E, at the index corresponding to U, or an attacker has forged an authorized native signature on a different BIP143 digest or broken the relevant hash commitment. This is because SIGHASH_SINGLE commits the exact output at the signed input index, while ANYONECANPAY omits other inputs. Reordering input/output pairs as a unit does not remove this guarantee. Since value(E)=value(U)=M, no value from U remains to fund any other outputs or fees; other funding inputs must supply them.

This lemma does NOT prove the script/graph has no bypass; that must be checked before irreversible funding. It does not prove the genuine future payout or cancellation path is safe. No new ZK proof is required merely to verify the N pre-signed native signatures, but an eventual FE capsule still needs correct construction and the intended one-honest audit/erasure assumptions.

### Important limit of the correction

A fixed signing key may preauthorize ANY amount-preserving activation variant with output E and a new nonwitness claim marker, but no one may infer that its unknown future cancel outpoint has a precomputed cancellation signature. BIP143 commits outpoint(u_W) even with ANYONECANPAY. Therefore the requirement of N offline setup plus future claims STILL needs an actual DYNAMIC protected signer (or a different fully analyzed native spending architecture) for the cancel edge, and potentially a separate bounded payout policy.

In particular, Bitcoin cannot introspect an OP_RETURN assertion to restrict a later payout recipient or amount. If the ScriptEscrow timeout path gives unrestricted authority to a notary, that notary can redirect value unless the full approved policy explicitly permits it. A legitimate whole-UTXO settlement to an independently authorized fixed owner is a possible narrower case, NOT a general variable-recipient bridge solution. Do not claim that a pre-signed activation graph alone implements safe settlement.

## Actual bounded computation

Executed a standard-library Python/BIP143 computation plus real secp256k1 ECDSA signing/verification from installed cryptography 46.0.4. Three setup public test keys and one notary key, two synthetic activations with different OP_RETURN claim digests and external fee inputs, plus three separate synthetic cancel keys:

- Three setup signatures over 0x83 verified on both activations.
- One notary SIGHASH_ALL signature verified for its actual claim, not the other.
- Changing the paired E script/amount rejected all three setup signatures.
- Negative control 0x82 (SIGHASH_NONE|ANYONECANPAY) wrongly ALLOWED changed E, confirming why 0x83 is essential.
- Different activation txids produced different SIGHASH_ALL cancel digests, and signature verification rejected cross-claim reuse.

Two completed executions yielded byte-identical JSON (SHA256 7eb74be987b93b956d3cd7d06bc6917af2403495f56c4a205a96606f2586ba96). Executed source script SHA256 3250e85701c332febe09b09185519f17bdd9081a162c9c16c04ffddb13919e5f. The full, more detailed derivation, source, output files and manifest are LOCAL ONLY in archive SAI83_firsthop_presign_20261120.tar.gz, SHA256 2715b6e2ac16c14ed46075b9163129e278219b0a84d5583a622b478a96c3896c. These bytes are not claimed as pushed to GitHub. The fixture uses publicly known test keys and fictitious outpoints. It is NOT Bitcoin Script VM execution, a funded transaction, source evidence, any FE/WE implementation, or a quantum test. The toy escrow script semantics are not verified and MUST NEVER be funded.

## Original release obligation — unchanged

Neither an actual serialized classical PPT Build_inc(x_W,S)->C and public Open_inc(C,w)=S for all qualifying ORIGINAL source witnesses, nor a complete-public FALSE/hard-TRUE QPT/native-forgery recovery-to-ORIGINAL security proof was constructed. The three approved independent challenge OR grounds and all contextual AuxPoW, burn, source relevance, anchors, windows, depth, reset, claim/recipient/amount, native VK/message and capsule binding remain necessary; a single accepted source challenge must still release every fixed participant contribution without online cooperation.

A future practical bridge needs dynamic, source-conditioned, nonspliceable restricted signing on u_W for any qualifying witness, and a correct payout graph. The goal is not met, this endpoint note is not a missing-release breakthrough, and no PR progress comment, production/Core edit, deployment or automation change is warranted.
