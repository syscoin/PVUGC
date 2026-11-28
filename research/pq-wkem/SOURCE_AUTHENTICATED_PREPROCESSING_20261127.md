# Source-conditioned authenticated preprocessing — 2026-11-27

Nonqualifying static construction/repair iteration. No completed WKEM, deployment assertion, or new Core/source semantics.

## Continuity and selection

Actual syscoin/PVUGC PR #1 is open/draft/unmerged on research/pq-wkem-validation-20260918, start f18c568d0b888ae4680951c5553957ad0bd4d776. Read actual metadata, recent substantive comments through R225, exact start commit file metadata and SOURCE_CLAW_NATIVE_CHAIN_20261127.md (blob 73b17fa2cec210fd25fc0d2b223e8976e65eaf19), plus SOURCE_OPENING_FIBER_RELEASE_20261127.md and SOURCE_OR_TRANSCRIPT_TRANSFER_20261127.md at the same start ref. Immediately before this single-file preservation, rechecked unchanged PR head and path absence (404 NOT_FOUND). No source rule change or new Core claim.

Missing operation: before future ORIGINAL witnesses exist, construct a serialized hash-only public evaluator which recovers the actual frozen cancellation capability on each full qualifying witness, with full-view simulation and extraction/break on unauthorized key recovery or native forgery. Try authenticated secret-sharing preprocessing instead of public equality/claw completion, private additive evaluator coefficients, or independently opened garbled labels. The proposed mathematical change to avoid R289 is to authenticate the entire evaluation under one transcript-specific authentication key, rather than certify independent wire labels; use correlated multiplication triples to propagate authenticated state, and use the final authenticated accepting value to unmask the native capability. Test whether the authentication can actually be preserved when the sender is offline, and whether a common final unmasker exists. The key must be hidden from the public adversary, not just a secret of an ideal MPC party. Static preflight, not an assumed authenticated evaluator.

## 1. Explicit offline preprocessing candidate

Let R(x,w) be the complete finite ORIGINAL predicate, including all three independent grounds, claim binding, relevance and maturity. Compile to a Boolean arithmetic circuit over F_2; tags live in a field F=GF(2^lambda) containing its Boolean inputs. A classical builder knowing sigma samples field authentication key alpha, wire offsets rho_i, and for each multiplication gate a,b uniformly with c=ab. For a fixed authenticated evaluation context the proposed tag on a wire is

    T_i(v) = rho_i + alpha*v.

The proposed masking endpoint is K=T_o(1), E=sigma XOR H_mask(ctx,K), with context framing, where o is the actual final R output wire. Every genuine w should produce (1,T_o(1)); a false w should at most produce (0,T_o(0)). To avoid a public fake-accept input the output tag must be computed through the circuit, not made available simply by supplying the bit 1. A full-public attacker may inspect the preprocessing, choose arbitrary false witnesses, run many evaluations, or synthesize arithmetic values without running the prescribed honest code.

In ordinary authenticated secret-sharing protocols the global MAC key and shares are held by noncolluding live parties. Multiplication of secret shared x,y opens d=x-a,e=y-b and uses the identity

    xy = c + d*b + e*a + d*e.
    alpha*xy = alpha*c + d*(alpha*b) + e*(alpha*a) + d*e*alpha.

Here the same identity is used as a candidate for serialized public authenticated preprocessing, not as an assumed online protocol. For offsets, authenticated output tags satisfy

    T_z(xy) =
      T_c(c) + d*T_b(b) + e*T_a(a) + d*e*alpha
      + rho_z - rho_c - d*rho_b - e*rho_a.

The sender can compute the triple and offsets without w. For honest Open, d,e must become available along the actual evaluation. Publishing all triples as clear values does not alone give a hidden accepting tag. Publishing alpha and output-zero tags trivially defeats the endpoint. The proposed repair was to keep alpha hidden, publish only the correction information necessary for public computations, and bind all tags to one full witness transcript.

## 2. Static rejection of the global-key and local-key instantiations

For arbitrary source-certificate bytes the circuit input wire i must accept both 0 and 1 before R has decided whether the certificate is genuine. In the simple globally keyed instantiation the public evaluator starts with T_i(w_i). A source-independent public input-tag table contains T_i(0) and T_i(1); even if accessed only through honest evaluation on two candidate inputs differing at i, both tags are available. Their difference is alpha. The two candidates need not be authorized (indeed the attack is intended for FALSE instances). No quantum query log or representation of an arbitrary attacker is required. If a chosen invalid complete witness is evaluable all the way to tag T_o(0), the global alpha gives K=T_o(0)+alpha directly, followed by the actual unmasking. If invalid evaluations instead never make their output tag available, the builder must implement that *cryptographic* refusal before the tag becomes exposed; an honest-code check of R after evaluation is insufficient. This rejection is for the explicit uniform-slope public input interface, not an impossibility for general authenticated computation.

Try distinct random slopes alpha_i, offsets rho_i. Then input-tag exposure reveals only each input slope. For an addition z=x+y with output slope alpha_z, the natural linear tag-conversion rule uses scalars A=alpha_z/alpha_x, B=alpha_z/alpha_y, assuming nonzero slopes:

    T_z(x+y) = A*T_x(x) + B*T_y(y)
                + rho_z - A*rho_x - B*rho_y.

If A,B are public, the supposedly hidden alpha_z is directly recoverable from any known incoming slope; the public offsets do not prevent that. If A or B is kept secret, this proposed public rule does not run. Nonlinear translation via a table of local hash masks can instead hide slopes, but its authentication is then per wire/occurrence; independently chosen intermediate values can be combined unless a whole-source invariant is implemented. That local-table repair has the R289 splice issue unchanged; reject without building another fixture. Multiplication triples do not resolve it: ordinary authentication of a public d,e only authenticates the arithmetic under the MAC key, not the provenance of d,e from a complete qualifying original witness. An honest online party enforcing its share/check is not allowed.

## 3. Attempt the genuinely different full-transcript binding repair

Use a collision-resistant, canonically framed digest delta=H_trace(ctx,w) of the *complete* original witness (or a canonical padded trace deterministically derived from it). Do not replace the original verifier with a digest test. Assign independent authentication contexts per delta, e.g. via a hidden hash-PRF master seed s:

    alpha(delta) = F_s("alpha",ctx,delta)
    rho_i(delta) = F_s("rho",ctx,delta,i)
    T_i(delta,v) = rho_i(delta) + alpha(delta)*v.

Use nonzero alpha by an explicit rejection rule if required. This mathematical change prevents treating a label under one delta as a label under another in an ideal authenticated evaluator. All wire transitions must use the SAME delta, checked inside their derivation. Even granting complete separation, two requirements arise simultaneously:

(A) Build must let public classical Open compute all needed authenticated input and transition corrections for a future delta, without learning s or recovering both arbitrary value tags under that delta. Simply publishing s exposes every tag, including T_o(delta,1), even on arbitrary false evidence. A hash of s does not enable public evaluation. Giving independent PRF outputs or per-delta material in advance for all possible traces is not practical polynomial setup. A conventional GGM constrained key for a publicly known prefix subset does not enforce the relation R over complete source witnesses. Publishing all local corrections under a single universal context is the previous local-key variant, not this repair.

(B) Even if (A) were achieved by some concrete source-dependent authenticated evaluator, its accepting output tag K_delta varies with delta. It is no longer a common key. Build knows s and sigma but not future witnesses, so cannot enumerate every relevant delta to publish E_delta. For one fixed public E, the honest unmasking identity would require

    H_mask(ctx,delta,K_delta)=E XOR sigma

for EVERY qualifying delta. In the independent QROM idealization, two distinct fixed qualifying digests and PRF-derived K_delta independent of that mask domain have distinct mask addresses; their uniform masks agree with probability 2^(-ell) for ell-bit payloads. Thus using independent transcript contexts directly with a single ciphertext has negligible two-witness correctness. This is a correctness observation in the specified independent-mask construction, not a proof against correlated masks or concrete SHA. Publishing a public function E(delta) that evaluates the right mask correction for each delta, without disclosing sigma or an accepting tag on false inputs, is the missing source-conditioned common-capability evaluator in another form. It cannot be assumed as an MPC primitive.

One could try a common output authentication context for all delta while preserving independent interior contexts. This requires a public transition T from a correctly authenticated final interior value to the fixed output tag; it must authenticate the full source computation, not only a chosen bit or public digest. The original Beaver formula with a shared alpha does not supply such a transition, and a local translation keyed by a public digest alone can be called on manually fabricated input. A table indexed by all trace contexts is exponential; a secret service is disallowed. No constructed T resulted. Therefore the transcript binding is meaningful only if one actually implements both (A) and the common output transition with jointly simulatable correlations. Do not present this as an assumed secure MAC-based WKEM.

## 4. Simulator and scope disposition

The global-slope interface exposes the actual candidate key by explicit algebra; no simulated public distribution can make that recovery hard while preserving this interface. In the transcript-specific interface independent PRF/RO marginals might be easy to simulate in an ideal model, but the required public correction/evaluation data are absent and the one-ciphertext construction is incorrect. Such a marginal simulator therefore proves nothing about a serialized capsule. Malicious source retention, related capsules, public native VK/message and auxiliary information must be included in a genuine joint reduction; none is proved here. No claim of extraction from arbitrary native forgery or same-message signature variation. No new verifier-only work, test/parameter sweep, web, external literature, code execution or subagents. Authorized GitHub continuity reads and static derivation only before preservation.

Next selection should not revisit the global MAC key, local wire-specific slope conversions, or independent transcript tags plus a single ordinary hash mask. Only pursue authenticated preprocessing again if there is a concrete hidden-key public gate translation **and** a common output transition preserving full-source binding and full-view QPT simulation. Do not postulate either as a primitive. All three original OR grounds, claim and maturity rules, R316 coverage correction, R225 activation-specific or explicit slot-global veto scope, one-honest N-of-N setup, pre-funding correctness/DA and network/inclusion assumptions remain unchanged. No ordinary PR comment or qualifying notification.
