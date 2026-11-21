# FE covenant gate: one-honest setup and claim-bound native signing

## Status

This is an assessment prompted by the user's 2026-11-18 FE question, with a
conditional setup design and an executed native-message binding check. **It is
not an implemented FE scheme, an ORIGINAL-source release construction, a work
bound, or a breakthrough.** The missing public cryptographic gate remains missing.
No routine breakthrough/progress comment is warranted.

The first-release endpoint may use ordinary Bitcoin signatures as newly authorized
by the user. This removes the need to wait for a native PQ signature opcode for
that release. It does not establish full-system QPT security or silently authorize
lattices/pairings as a replacement for the requested hash-only release foundation.

## 1. What the supplied proposal actually supplies

Jeremy Rubin's *FE'd Up Covenants* (May 29, 2024), sections 1.1.1, 2, 2.4 and 3,
describes function-hiding/dual-input FE protecting a signing secret, optionally
checking a succinct proof before signing. It assumes erasure and identifies the
required cryptography as impractical. It does not specify a concrete FE compiler,
a malicious ceremony, or a quantitative source-work extraction theorem.

The supplied Cointelegraph article dated November 18, 2026 describes that same
conditional approach. Its summary cannot turn the assumed FE functionality into
a secure implementation. We do not infer a general impossibility for a restricted
Syscoin relation from the difficulty of generic FE or generic obfuscation.

Primary sources read for this assessment:

- https://rubin.io/public/pdfs/fedcov.pdf (all five pages as extracted text).
- https://eprint.iacr.org/2010/543 (FE definitions/challenges abstract).
- https://eprint.iacr.org/2013/258 (original WE abstract and FALSE definition).
- https://bips.dev/143/ (native witness-v0 digest definition and test vector).

The article and abstracts linked from it were examined to identify the required
primitive; no claimed current implementation was inferred from a paper title.
Full IACR PDFs for the definition/multi-input/PIPEs papers returned HTTP 403.
The PIPEs v2 abstract identifies WE and an AADP research direction; it does not
provide evidence here of a verified practical hash-only bridge implementation.

## 2. Exact protected functionality

Let x contain the exact chain/protocol IDs, claim/UTXO, withdrawal/burn assertion,
amount/recipient/reserve/replay state, qualified baseline and BTC anchors/window,
relevant height, LC fork-depth policy, deadline/reset, safe native transaction and
verification key(s), and a preselected capsule/session identifier.

Keep the approved ORIGINAL relation as a disjunction:

    R_x(w) = R_BTC,x(w) OR R_burn,x(w) OR R_inconsistency,x(w).

The third branch checks qualified incompatible histories or an independently
authenticated applicable tag fault. It does not require greater Syscoin work.
The first branch has same-anchor strictly greater exact Bitcoin chainwork. The
second branch requires finite authenticated burn refutation/nonmembership or
bounded execution, not a missing ordinary Merkle path. These are separate grounds.

For a known cancellation message m_x and participant i, precompute sigma_i and
define the **public-function, private-payload** circuit:

    G_x(sigma, w) = sigma if R_x(w)=1; bottom otherwise.

A dual-input FE layout would be:

    (mpk_i, msk_i) = FE.Setup(lambda; r_setup,i)
    ct_i = FE.Enc_1(mpk_i, sigma_i; r_enc,i)
    dk_i = FE.KeyGen(msk_i, G_x; r_key,i)
    C_i = (mpk_i, ct_i, dk_i, exact public context)
    Open_i(C_i,w) = FE.Dec(dk_i,ct_i,FE.Enc_2(mpk_i,w)).

If these algorithms existed with appropriate correctness/security, every valid
original witness would return the same sigma_i. No common source preimage, unique
fork witness, or equal internal state is required. For this fixed-output case the
resulting interface is precisely a scoped witness-encryption/release mechanism
for R_x. The notation does not instantiate its encryption algorithm.

For future claims/messages not known during setup, use a **different**, stronger
interface:

    F_i(sk_i, A_x, T, w) =
        Sign(sk_i, NativeSighash(T, full_prevout_context))
          if ExactActivationAndSafeCancel(A_x,T,x)=1 and R_x(w)=1;
        bottom otherwise.

The full agreed policy also defines initiation by one authorized notary and any
other permitted graph transition. The cancellation path has no extra owner or
notary signature requirement. Timelocks enforce maturity on Bitcoin; the offline
program cannot trust a caller's asserted current time. Timeout payout does not
require proving absence of challenges.

Use a vetted deterministic signing algorithm, binding nonce derivation to the
key and exact message, when byte-identical output for a fixed activation is
wanted. Do not reuse one fixed ECDSA nonce across different messages. Dynamic
signatures are fixed by the message and key, but their bytes were not precomputed
before an unknown claim existed. This distinction must remain explicit.

## 3. One honest setup participant without threshold signing

Each participant generates an independent native key pair (sk_i,pk_i), independent
FE setup, and one appropriately bound public capsule. Use a native N-of-N script
on every protected edge until authorized final whole-UTXO settlement. There must
be no subset-controlled bypass, independent key path, or alternate transaction
that circumvents the honest component. Native script/policy limits bound N.

One challenger with one valid w evaluates ALL public capsules locally and obtains
the required vector of N native signatures. No setup participant responds online;
N signatures do not constitute an N-party challenge quorum. No aggregation is
assumed. The other N-1 participants may retain/disclose all their own secrets.

Conditionally, an unauthorized spend still needs the honest participant's native
signature. It must therefore exploit that participant's public capsule, break
the native scheme, or exploit an error/bypass in the agreed graph/policy. This
reduces the distributed problem to an independently secure honest component;
it cannot protect a component that is publicly breakable.

### The exact proof of capsule construction

For a fixed-signature capsule define the public statement

    Y_i = (sid,i,pk_i,m_x,mpk_i,ct_i,dk_i,h_policy,h_graph,h_code).

The witness consists of sk_i, sigma_i, msk_i and all generation/encryption/key
derivation random tapes. Check the finite relation:

    pk_i = Sig.PublicKey(sk_i)
    Sig.Verify(pk_i,m_x,sigma_i) = 1
    (mpk_i,msk_i) = FE.Setup(r_setup,i)
    ct_i = FE.Enc_1(mpk_i,sigma_i;r_enc,i)
    dk_i = FE.KeyGen(msk_i,G_x;r_key,i)
    AcceptedParametersAndCanonicalBytes(Y_i,witness) = 1.

For the dynamic case, encrypt sk_i, use F_i as the exact agreed function, and
omit the fixed-message signature equality. Bind the exact signature algorithm,
sighash flags and serialization, relation/verifier version, public proof-system
parameters, and policy/circuit image. A program name or prose description is not
a code commitment.

An appropriate zero-knowledge proof of this relation lets the honest participant
check that the published bytes were generated for the intended key and program
without learning the secret. A transparent proof system, or a correctly secured
one-honest setup for its parameters, avoids adding a new trusted proof authority.
This is a relation specification, not an implemented ZK proof in this iteration.

Funding acceptance requires the exact graph and manifest, all accepted proofs,
all required pre-signatures where used, and complete retrievable capsule data.
All these checks precede irreversible funding. Malicious refusal can abort the
ceremony before funding; it cannot be made to cooperate by a correctness proof.

### Three limits the setup proof does not remove

1. An NP proof that generation used **some** random tapes does not establish that
   those tapes were uniform. Secrecy relies on the honest party's fresh independent
   randomness. Useful completeness for malicious components additionally needs
   correctness for every accepted parameter/tape choice, or a sound validity
   mechanism excluding bad choices. Honest-randomness correctness alone is not
   enough if an adversary can select an unopenable accepted capsule.
2. Public classical transcripts cannot prove that all secret copies were erased.
   The one-honest assumption includes erasing/protecting that participant's
   signing key, FE master secret and any bypass material. Others need not erase.
3. A proof of executing Compile correctly cannot prove the cryptographic security
   of Compile. If the published FE key leaks its payload, a perfectly valid
   construction proof does not repair it.

## 4. Future-claim native binding and the endpoint computation

Dynamic signing permits a concrete repair of the R225 common-outpoint issue.
Put H(claim) in the **nonwitness output commitment** of activation A_x. For example,
the P2WSH witness script may contain:

    PUSH32(H(claim)); DROP; N; pk_1; ...; pk_N; N; CHECKMULTISIG.

The activation output commits to the hash of that entire script. The cancel
transaction spends u_x=(txid(A_x),v). Different claim commitments change the
activation's nonwitness bytes and hence its outpoint under hash binding. The
protected signer checks that actual outpoint and claim before signing.

Use an independent session/capsule nonce selected before compilation. After
compilation, a manifest commits to exact capsule bytes; do not demand that the
capsule contain a signature over its own final hash. The funding identity must
be stable before generating capsules that hardwire it, or the dynamic policy
must authenticate it from a noncircular session/graph root. In either approach,
keep funding unbroadcast until acceptance.

The frozen-signature option remains appropriate for an already fixed native
message or an explicitly approved slot-global veto. Off-chain binding to a wtxid
does not, by itself, restrict a signature on a common fixed outpoint.

`native_binding_check.py` actually ran with Python 3.12.14 and cryptography 50.0.0.
It first matched the published BIP143 Native P2WPKH digest, then constructed two
synthetic claim-committed activation outputs and their cancellation digests. It
generated deterministic low-s ECDSA signatures under three public test keys.
The signatures verified on their own message and failed on the other claim,
on the isolated changed-outpoint digest, and on a changed-recipient digest.
One duplicate-signature substitution failed the third key's verification.

The computation is **not** Bitcoin Script/VM execution, transaction admission,
funding, original source validation, FE evaluation or a collusion-security proof.
The input UTXOs and claim strings are deliberately fictitious. The matching
standard digest vector and real ECDSA checks validate only the message-binding
calculation. The output is captured in `native_output.json`.

## 5. Why generic FE language does not yet prove source security

### Ordinary function keys need not hide the function

Take an ordinary input-hiding FE scheme and append the complete function
description to every functional key. This leaves its ordinary input-hiding game
unchanged: the selected function is already known there. If sigma was hardwired
in that function, the appended description reveals sigma. Thus that security
notion alone does not justify putting secret signing material in a public
functional key. Genuine function hiding or a separately encrypted private
argument is needed. This is a definition-level counterexample, not an attack on
all FE systems.

### A proof outside the protected function is bypassable

The tempting small arithmetic gate is Q(sigma,b)=b*sigma, with a normal program
checking a source proof and supplying b=1. Given the public functional key, an
attacker directly forms Enc_2(mpk,1) and obtains sigma from FE.Dec. Neither FE nor
the proof system is broken. The cryptographic gate implemented the wrong policy.

The same problem applies to supplied SHA/proof-verification feature vectors:
their consistency with a single original witness must be enforced within the
protected computation. A public wrapper and a proof of correct setup do not
prevent arbitrary direct processing of the public package.

The legitimate repair is

    G_x(sigma,pi) = sigma if Verify(vk_R,x,pi)=1; bottom otherwise.

This can reduce the protected circuit size but requires an actual FE system for
that verifier. It also requires an appropriate argument-of-knowledge reduction
from an accepted pi to ORIGINAL w. Soundness for false statements is insufficient
to establish that a proof of a true, computationally hard statement requires
obtaining the desired witness. Direct original evidence avoids the inner-proof
extraction layer, while making the protected circuit larger.

### TRUE existence and efficient witness acquisition are different

A security guarantee restricted to payload pairs with identical function outputs
on **every** allowed secondary input cannot be applied to sigma_0 != sigma_1 if
there exists w* with R_x(w*)=1:

    G_x(sigma_0,w*) != G_x(sigma_1,w*).

This remains true when finding w* is prohibitively expensive. This observation
does not rule out stronger FE notions, prove that a particular FE system leaks,
or establish a source-specific impossibility. It means the actual definition and
reduction must address hard-TRUE evidence, not only FALSE instances or semantic
output compatibility.

## 6. Exact unproved security equation and model

For first-release classical security, the desired concrete reduction has form

    p_cancel(A;T,Q,Aux)
      <= L * p_original(E_A;T',Q',Aux')
         + eps_hash + eps_native + eps_setup.

E_A must output an actual qualifying original certificate. T',Q', L and all
simulation/extraction losses must be explicit. Merely showing they are polynomial
does not establish practically equal work/odds. Here the gate error must be
reduced to independently justified assumptions of an actual implementation;
adding an unexplained eps_FE term would leave the central obligation intact.

One sufficient but **uninstantiated** classical proof route would simulate the
entire public package using only an honest policy-signing oracle. Simulate it with
all-reject answers and stop before its first accepted ORIGINAL input. Up to that
first input the real and rejecting simulations coincide. Either this run supplies
an original certificate, or accepted native output without such a query is a
native forgery, provided the simulator built the whole joint view without signing
the target message. This gives a useful proof plan, not a compiler. It cannot be
assumed as the missing primitive under a new name.

More precisely, fix a designated honest participant h and target native message
m. Give S[A] public/context inputs I that can be generated without the sampled
honest secret, target signature, or real target capsule. If its explicitly
constructed joint simulation has error eps_sim, let Q be its first accepted gate
query event. Coupling its real-gate and reject-gate executions gives

    Pr[Q] = Pr[E outputs original w]
    p_cancel <= Pr[Q] + Pr[accepted native signature AND not Q] + eps_sim
             <= p_E + Adv_native(B) + eps_sim.

There is no q success-probability loss in this classical stopping argument. The
extractor does pay the simulator overhead and up to q full relation checks:
T_E <= T_S[A] + q*T_R, plus source/environment costs. A native forgery reduction
must never request a signature on m. S's advice may depend on A and the public
sampler, not on the sampled hidden key/signature. Giving S the actual target
capsule as auxiliary input makes the premise vacuous. Capsule hashes and graph
commitments correlated with it must be jointly simulated. Adaptive sibling
creation needs an interactive joint theorem; arbitrary adaptive corruption may
add an honest-participant guessing loss. No adaptive-corruption theorem is
claimed here. Extraction after a deadline is not proof of timely challenge
inclusion; that is a separate network/timing obligation.

The joint view includes native VK and checking/context correlations, every setup
proof and manifest, sibling capsules, selectively released signatures, all
corrupted setup coins and malicious source-generation coins. Honest bypass
secrets and fresh FE tapes are not given to the adversary. Allowed auxiliary
dependence must be modeled explicitly, not declared independent after the fact.
An already legitimately released signature for the same native authorization
class must not be misclassified as an unauthorized forgery.

For eventual QPT capsule security, honest algorithms remain classical PPT and
attackers may process all public bytes and source/hash interfaces coherently and
jointly, with admissible nonuniform advice. Classical query logging/rewinding does
not automatically lift. A conditional real-vs-reject oracle hybrid with q coherent
queries can lose a quadratic factor in extraction probability: a bound of form
Delta <= 2q*sqrt(p_extract) gives p_extract >= Delta^2/(4q^2). This is only a model
calculation if a concrete simulator/oracle interface has first been constructed.
It is not programmed-oracle security for concrete SHA. Ordinary EC Bitcoin
outputs do not thereby acquire end-to-end post-quantum protection.

Finally, the approved OR relation does not imply every canceller must freshly
mine. A valid certificate can be copied, burn refutation may require no mining,
and inconsistency does not require greater Syscoin work. A source-resource bound
must concern obtaining qualifying evidence in the specified history/anchor/window
distribution, with retained coins, prior work, data availability, propagation and
inclusion/censorship assumptions. FE cannot infer BTC best-chain membership from
raw parent work or repair missing data by itself.

## 7. Precise stopping point

The conditional architecture and endpoint binding are coherent. The required
classical practical public Compile/Eval gate and its complete-public FALSE /
hard-TRUE security are not implemented. Verifiable setup cannot be completed
against a nonexistent FE compiler. Neither the native checker nor three
independent reasoning reviews changes that status.

Next constructive equation remains:

    C = Compile_R(x,sigma;rho),  Eval_R(C,w)=sigma for every R_x(w)=1,

together with the concrete joint-public recovery-to-ORIGINAL reduction above.
The next substantive advance must instantiate that equation, or reduce its
ORIGINAL-source obligation in a proved, independently grounded way. It must not
be another ideal evaluator, feature-bit wrapper, basis-mask experiment, or setup
proof around an unprotected secret.

No Core tests, network source certificate, production changes, automation change,
deployment or funds transfer were performed. Publication of this note records the
user-requested FE analysis; it is not a progress announcement.
