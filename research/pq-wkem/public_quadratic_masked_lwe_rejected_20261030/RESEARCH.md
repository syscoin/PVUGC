# Offline candidate: public-quadratic masked dual-LWE release (REJECTED)

**Classification: no positive witness-KEM construction advance.** This iteration attempted to repair the earlier signed-unit linear pseudo-opening by making the public release evaluation nonlinear in the SAME candidate opening. The proposed public quadratic mask can be bypassed by replacing the quadratic monomials with their legal values while retaining a different linear pseudo-opening. The actual native secret is recovered on a fixed FALSE ORIGINAL statement. The finite checker is supporting evidence, not a security theorem or a QPT attack on the surviving uniform-target SOURCE.

## Provenance

- Run: automation turn 10, record `public_quadratic_masked_lwe_rejected_20261030`; no execution UUID supplied.
- Repo `syscoin/PVUGC`, PR #1, branch `research/pq-wkem-validation-20260918`; PR read open/draft/unmerged; observed start `f6289a420ddaa9534b7d5269fd0b09a714cc5a56`.
- Latest ordinary substantive PR comment inspected: `6519067442`.
- Exact predecessor files at start head: `adaptive_left_action_20261030/RESEARCH.md`, blob `febc8ab3bd758f2d2d60c4344b57f47bb11e133a`; `uniform_target_batched_lwe_20261030/RESEARCH.md`, blob `d1bc72cf6b2692ee73783d086931014917631859`.
- No web/literature research, no whole-PR diff, no archive sweep, no agent invocation. Standard-library Python 3 checker executed twice byte-identically.

## ONE attempted repair: public nonlinear checksum tied to the same z

Begin with a bounded Boolean verification circuit; a single AND gate `a AND b = c` uses Boolean slacks `(s1,s2,s3)` with equations

    a-c-s1=0,
    b-c-s2=0,
    a+b-c+s3=1.

All variables are bits. Signed-unit coordinates `z_i=2v_i-1` yield the public integer linear relation `C z=t`, and the genuine Boolean condition is additionally `z_i^2=1`. A general circuit can be expressed by combining these constraints, NOT by assuming a canonical witness. Different valid Boolean witnesses retain distinct signed vectors.

Take prime `q`, integer `g`, `m` source coordinates, row matrix `C` and target `t`. For each native signing-key bit `a in {0,1}`, sample classical coins

    r <- uniform F_q^n,
    v <- uniform F_q^m,
    eta,xi <- chi^m, eta_d <- chi,

with independent bounded `chi` supported in `[-B,B]`. Publish the complete per-bit capsule `(c,h,d)`:

    c = C^T r + eta (mod q),
    h_i = v_i + xi_i (mod q),
    d = t^T r + g*a - sum_i v_i + eta_d (mod q).

The proposed *public* release computes

    F(z) = d - z^T c + sum_i z_i^2 h_i (mod q),

with a claimed format check `z_i in {-1,+1}` and `Cz=t`. For **any valid ORIGINAL witness**, `Cz=t` and `z_i^2=1`, hence

    F(z)= g*a + eta_d - z^T eta + sum_i xi_i (mod q).

Thus if `g>2 B(2m+1)`, all valid ORIGINAL witnesses recover the same precommitted digit by nearest-center decoding. Repeating per digit recovers the same native serialized secret under genuine native key generation. A public checking-key link and claim/UTXO/path/context bindings can be included in the capsule; they do not affect these identities. Honest setup knows the native signing secret but **does not** need an ORIGINAL witness. This is a classical-PPT release algorithm with an algebraic correctness opportunity, not a secrecy proof.

### Why the proposed nonlinear protection fails

The adversary can disregard the format check: its input is public, and all ciphertext coefficients `c_i,h_i,d` are public. It can compute a *different polynomial evaluation* from those exact same public bytes:

    F_bad(z) = d - z^T c + sum_i h_i,

which replaces the quadratic value `z_i^2` by 1 **without replacing z_i in the linear part**. Whenever a public pseudo-opening satisfies `Cz=t`, even if some `z_i` are not signed units,

    F_bad(z)= g*a + eta_d - z^T eta + sum_i xi_i (mod q).

The supposedly secret uniform `v_i` disappear *exactly*. The honest checking-key correlations and related capsules do not help: the attacker recovers the authentic signed message secret, not a spurious candidate.

For the false ORIGINAL statement `a=0,b=1,c=1`, the signed constraints force a contradiction to `z_s1 in {-1,+1}`, but the public integral pseudo-opening

    z_bad = (-1,+1,+1,-3,-1,+1)

satisfies the complete linear relation `Cz_bad=t_false`. The fixed-input rows are themselves public. The false statement has no signed-unit opening. Yet `||z_bad||_1=8` and the attack error is bounded by `B(1+8+6)=15B`, so `g>30B` is sufficient for *deterministic* false-instance key recovery for all bounded noise coins. There is no reliance on probability, statistical averaging, source-oracle access, or classical rewinding. This is a successful classical attack and therefore also a QPT adversary.

With the checked illustrative parameters `q=65537`, `B=1`, `g=101`, true signed-unit decoding is sound (`13 < 101/2`) and pseudo-opening decoding succeeds (`15 < 101/2`). The public quadratic policy's evaluation at `z_bad` differs from the attack exactly by `sum_i(z_i^2-1)h_i`, confirming the bypass is an algebraically different evaluation, not an incorrect honest witness.

## Full public view and what the check actually exercises

The complete public input is `x=(AND relation,fixed inputs,scope)`, the fixed `C,t`, all c/h/d ciphertext coordinates for the complete secret, the checking-key mock `SHA256(sk)` and two related capsules independently randomized to the same precommitted 256-bit sk. The adversary need not know any source-opening secret, LWE coin, honest secret, or native signing oracle; it uses only `C,t,c,h,d`. More auxiliary data or a malicious N-1 coalition cannot remove this deterministic attack, and no assumption about the honest survivor is involved. The checker tests the complete 256-bit recovered secret twice and compares it with the independently computed mock checking-key digest. **SHA256(sk) is a functional mock and is not a genuine native/PQ signature implementation.**

The exact Python 3 standalone `check.py` was executed twice with byte-identical `OUTPUT1.json` and `OUTPUT2.json`. It passed 5,642 assertions per run, including exhaustive signed-unit nonexistence for the false six-variable claim, 1,280 randomized per-bit complete public transcript checks (640 false), and two fresh 256-bit related capsules, both recovering the same full precommitted mock secret. Randomness is deterministically seeded for reproducibility and is **not cryptographic**. This is a finite classical algebraic attack, not an empirical quantum-hardness evaluation.

## Attempted repair and exact handoff

The quadratic term was meant to amplify illegal `z_i^2 != 1` with fresh uniformly random hidden `v_i`. In this concrete construction `h_i=v_i+xi_i` is public, while the cancellation of `sum_i v_i` is publicly reconstructable. Every party can alter the monomial evaluation without revealing its chosen `z` to anyone. Moving the legal signed-unit condition into a software `Release` check does nothing because release is public and offline.

This attack does **not** prove all nonlinear encodings insecure, nor refute the honestly uniform SOURCE LWE hybrid. It does show that adding separable *public* polynomial terms to the linear source cancellation is insufficient even for one AND gate and for all native-key bits. The exact unresolved design obligation is a witness-free classical-PPT `Comp(R_original,x,scope,pk)` with a source-dependent **joint** QPT simulator and nonlinear release whose key-bearing cancellation cannot be assembled from incompatible public monomial choices. Every valid ORIGINAL witness must still yield the SAME real native capability; every fixed FALSE x must hide it against arbitrary QPT; hard-TRUE unauthorized final-key recovery/native forgery must yield an ORIGINAL witness or independent QPT break without requesting an internal representation.

Malicious any-one-honest N-of-N preauthorization, useful abort/completeness, source qualification, SYS/BTC authenticated fork evidence and the hypothetical PQ-native Bitcoin endpoint are untouched. No completion or deployment claim; do not disable the research automation.
