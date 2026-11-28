# Offline batch OT with an ORIGINAL receiver tape — 2026-11-27

Nonqualifying static construction/repair preflight. No WKEM, QPT proof, or deployment claim.

## Continuity and selection

Actual start: syscoin/PVUGC PR #1, open/draft/unmerged, research/pq-wkem-validation-20260918, head 0042a9788194125054729f2d77b3f3cd464e6d0c. Read PR metadata, recent substantive comments through R225, exact head changed filename and SOURCE_TRANSITION_CERTIFICATE_DELEGATION_20261127.md (blob bce2b5f47b91f81033238844f7dbf7d4dfb83a63), SOURCE_CONSTRAINED_FSS_TERMINAL_CORRECTION_20261127.md, SOURCE_PAIRED_INSTANCE_LIFT_CYCLE_20261127.md and SOURCE_OR_PROOF_CHALLENGE_TRANSFER_20261127.md at that head. Rechecked unchanged head; new path returned NOT_FOUND/404. No new Core claims.

Missing operation: offline classical-PPT Build of a serialized public capsule, public Open from EVERY qualifying ORIGINAL certificate recovering the same frozen safe native capability, and arbitrary full-public QPT security. Selection: use a single batch of correlated receiver choices over the ENTIRE canonical source certificate, rather than independent public wire-label input access. The proposed mathematical change to avoid the known occurrence/label splice is to make the receiver's correlated tape derive from one complete source witness, with a common hidden sender correlation across all coordinates. Do not assume OT or a trusted receiver setup: an ordinary interactive OT would not solve the offline problem. Test the exact hash-only sender response and an offline translation repair before implementing any garbled verifier or multiplying fixtures.

## 1. Concrete batch response and correctness

Let V_x(w) be the complete ORIGINAL verifier, with all three independent grounds and full authentication/relevance/claim bindings. Let r(w) be a fixed-length canonical encoding of w (and, if required, the deterministic verifier trace); use injective padding and context. For the diagnostic grant a perfectly correct garbled circuit for V_x with input labels L_(j,0), L_(j,1) and a fixed acceptance label K, and E = sigma_cancel XOR KDF(ctx,K,length). This grant does NOT establish reusable public-input garbling security. The point of the batch is to try to deliver just the consistent input-label vector, not to assume independent public access to all the labels.

For N input positions and k-bit column seeds, work over GF(2). Choose hidden nonzero sender vector s in {0,1}^k. The receiver's tape is two N-by-k bit matrices T,T' and choice vector r. In the ordinary correlated transfer algebra the receiver sends the columns U_i=T_i XOR T'_i XOR r. The sender knows the selected column (T_i if s_i=0, T'_i if s_i=1), and computes Q_i= selected_column_i XOR (s_i U_i). Then Q_i=T_i XOR s_i r. Equivalently for row j, q_j=t_j XOR r_j s. Define

    C_(j,0)=L_(j,0) XOR H_pad(ctx,j,q_j),
    C_(j,1)=L_(j,1) XOR H_pad(ctx,j,q_j XOR s).

H_pad is an independent hash domain expanded to label length; ctx contains the capsule identity and original native/claim bindings. Given the actual tape the receiver recovers L_(j,r_j) by XOR with H_pad(ctx,j,t_j). This identity is exact even without any hash security assumption. It is only the final response algebra, not an implementation of the selected-column secret distribution. In a conventional interactive protocol the sender already needs the selected columns and U; we are explicitly not importing that protocol or assuming an independent OT setup here.

For a serialized Build, try to choose an arbitrary reference r^0 and matrices T^0,T'^0 and s before any future w exists, generate U^0,Q^0, and publish both fixed masked labels per j. The intended Open derives a new consistent tape from the actual original w and reuses this response. No source witness was needed to generate the bytes, and no online party has the sender vector after setup. Determine whether a public correction can reconcile the future tape with the fixed response.

## 2. Offline translation repair

First hold the receiver matrices fixed and vary r. Write Delta=r XOR r^0. For the corresponding receiver message U_i=U_i^0 XOR Delta we would have

    q_j=q_j^0 XOR Delta_j s.

If Delta_j=1, the two hash pads are simply swapped. Swapping the two ciphertexts does NOT produce correct labels: it swaps their plaintext meanings as well. A public correction D_j=L_(j,0) XOR L_(j,1) would make the translated response correct: C'_(j,0)=C_(j,1) XOR D_j and C'_(j,1)=C_(j,0) XOR D_j. But anyone who obtains one label now obtains both by XOR with D_j, including an arbitrary evaluator given the reference tape before any source witness. This is an exact loss of the intended input consistency, not a claim that an adversary necessarily forges a complete original certificate. In the alternative correction with D'_j=H_pad(ctx,j,q_j^0) XOR H_pad(ctx,j,q_j^0 XOR s), the party holding one reference pad obtains the other pad and decrypts both ciphertexts. These failures do not depend on a weak hash or an affine approximation to it.

Consequently do not implement the public flip-mask variant. A correction which is available ONLY to the actual qualifying receiver is not ruled out by that attack, but must itself have a concrete source-conditioned serialized implementation; the public U and Delta are not such a secret. A normal interactive sender could compute the translated response without disclosing D or D', but that is a retained online secret actor and outside the target.

## 3. Different repair: allow the receiver tape to change with the complete witness

Keep the serialized ciphertexts fixed, with neither correction published. Then a correct receiver for choice bit b needs a t_j(w) satisfying

    H_pad(ctx,j,t_j(w)) = H_pad(ctx,j,q_j^0 XOR b*s).

In the no-distinct-input-collision case this is precisely

    t_j(w) = q_j^0 XOR r_j(w)*s                     (A)

for EVERY row of EVERY qualifying ORIGINAL witness. This is a single correlated batch condition, not independent per-coordinate gates. In particular, it implies that each row of the source-derived tape belongs to a two-element set known to Build even though different original witnesses need not share their tape. It also implies for any two witnesses w,w' that

    t_j(w) XOR t_j(w') = (r_j(w) XOR r_j(w'))*s.

These equations describe an exact prospective correlation that would allow a single response to cover differing inputs without public flip corrections. They concern the literal pad-input method above; no assertion is made that every conceivable transfer mechanism must satisfy (A).

Consider the concrete proposed source tape t_j(w)=H_tape(ctx,j,encode(w)) in a separate k-bit random-oracle domain. Build can query this domain before freezing Q^0, and may even know some valid witnesses. For a fixed fresh qualifying w whose row input was not queried by Build, conditional on its classical setup transcript and the input being fresh in that domain, the oracle value is uniform; the chance of matching the required row value is 2^-k. For N fresh distinct row inputs fixed independently of their answers the probability all match is 2^(-kN). If the witness is selected adaptively by searching the oracle, charge each fresh tested row and use a union bound over those trials rather than this product. This is a conditional classical correctness diagnostic, not QPT security or a probability model for real consensus histories. The exact deterministic relation (A) avoids needing any such estimate. Source-derived tape values generated by independent hashes are not an algorithm ensuring (A).

Setting the tape to (A) in ordinary Open code by including q_j^0 and s as readable constants also fails immediately: anyone decrypts both labels at every position. Publishing a reference tape and giving a future receiver a public function that returns the new tape for arbitrary r would disclose s whenever a bit flips, and thus all pads for this capsule. If the new tape is available only after genuine source qualification, disclosure of s AFTER a valid opening is not by itself a breach of this already-released capsule; one must still consider siblings and related setup coins. The problem is making that access available to ANY qualifying original witness in the first place, without access on invalid witnesses. A public verifier's if-check followed by computing (A) with embedded q,s is not a cryptographic restriction.

The strongest repaired interface therefore calls for a concrete serialized correlated-tape sampler that produces Q^0,s-dependent public data before the witnesses exist and lets a public algorithm derive (A) from qualifying ORIGINAL evidence. Its joint simulator would need to cover the masked label response, the full original context, all public tape data, any auxiliary or retained source coins, and siblings. This is not supplied by a hash PRG, conventional OT correctness, or garbled verification. In fact, if this sampler is simply assumed to hide q_j^0,s until source qualification, it is already providing the essential source-conditioned secret access. There is no implementation or independent QPT argument for that interface here.

## 4. Handoff

Do not replace the receiver tape with a fake puzzle, independent OTS credential, an interactive sender, a secret receiver device, or a source-oblivious reference tape. Do not repeat this algebra at larger matrix sizes or with another hash placement. No actual selected-column base transfer is assumed or instantiated. No new attack on interactive OT, standard hash assumptions, or general source-specific WKEM is claimed. The precise failed repair is offline reuse of a fixed correlated response via public translation; the alternative needs the source-bound batch correlation (A), jointly simulated from the full public view. If pursuing transfer mechanisms, look for a materially different source-specific public response that does not require secret-dependent translation or assume (A). A successful input-label transfer still would need an arbitrary-adversary, globally consistent garbled evaluation argument and the fixed native endpoint proof; the current note claims neither.

All three original grounds and relevance/maturity, R316 LC correction, R225 endpoint choice, one-honest N-of-N setup/capsule correctness before funding, full auxiliary/multi-capsule security, exact native recovery vs accepted forgery, and timely evidence/inclusion remain unchanged. Static derivation only; no checker, code execution for crypto, tests, subagents, web, or literature invoked. No ordinary PR progress comment.
