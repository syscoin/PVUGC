# COMPOSE-CG-20261114: constrained hashes + a garbled correction program

**Rejected composition, not a secure WKEM.** The interactive user asked whether earlier constructions can be combined into a real solution. This pass actually combined R275's constrained-hash correction idea with R280's SHA garbling, then examined N-of-N preauthorization as a consistency repair. Polynomial setup and same-output correctness hold for the specified candidate. Its complete public representation nevertheless reveals the secret on a FALSE instance.

## Provenance and unchanged requirements

Start: syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, head b06306610b8886cb2dd82fc65472f23faf03b4cc. Read exact-head R263 and latest relevant ordinary comment R225 (6796383617), plus the attached local R275/R280/R287 notes. No external research, independent agent, Core test or deployment claim. An intermediate checkpoint was committed and read back at 9696b770678572d509eadcfc4e1848a3a1f0c390, blob 1bcc2a5acfceeaa887db9c8429491b6698cc9d91.

The ORIGINAL relation remains the three OR challenge grounds (higher qualified BTC work, authenticated burn fault, qualified SYS inconsistency/tag fault), with complete source/claim/UTXO/amount/recipient/anchor/window/depth and native-message binding. One notary initiates; anyone may challenge; N-of-N is the preauthorization ceremony. Core #609's canonical activated tags and modern chain ID are preserved, as is R287's distinction between child identity and exact faulty-wrapper provenance. This experiment does not instantiate that entire source verifier, or relax it to a cheap hash puzzle. Its FALSE test is an elementary consistency regression that any proposed compiler must handle.

## Concrete polynomial Build/Open

Let the source verifier's constraint decomposition be Phi_x(w)=AND_i C_i(w). For each local constraint choose an independent keyed function F_i with public restricted keys permitting F_i(w) on C_i(w)=1. R275's explicit correction table was

    D[w] = K XOR F_1(w) XOR ... XOR F_m(w),

and had exponentially many rows. The proposed synthesis replaces the table by a garbled computation. Freeze a payload S, representing the same intended cancellation authorization, and define

    E_S(w) = S XOR H_out(F_1(w) XOR ... XOR F_m(w)).       (1)

Build compiles this function, garbles its Boolean circuit, publishes BOTH labels only for external witness bits, ONE active label for each fixed private seed/payload bit, the garbled rows, final-output decoding and local constrained keys. It does not publish internal label pairs, root seeds or S. Honest Open evaluates E_S(w); if all local functions can be evaluated at the same w, it computes their XOR and unmasks S.

This is a concrete polynomial-size setup in the circuit size, with no future-witness enumeration. Every satisfying w returns exactly S, even though its function values and intermediate labels differ. This is not merely R280's direct seal to an accepting output-wire label. R280 did NOT publish clear payload bits; the present improvement is to garble a witness-dependent correction function with secret fixed inputs instead of sealing directly to a predicate output.

These correctness facts do not imply security of the combined public keys and garbling. A one-evaluation garbling argument would not establish the reusable full-public property required here.

## Executed SHA256 instantiation

Use w=(b,u), with b one bit and u eight bits. The FALSE local predicates are C_0(w)=[b=0] and C_1(w)=[b=1]. Each is locally satisfiable but their conjunction has no witness. Independently choose 256-bit roots s_j, and derive

    k_{j,b}=SHA256("CG-child" || ctx || j || b || s_j),
    F_j(b,u)=SHA256("CG-F" || j || ctx || k_{j,b} || u).

Publish k_{j,a_j} for the allowed branch of each predicate. The FALSE test has (a_0,a_1)=(0,1); the TRUE variant has (0,0). This is a simple clause-first, locally restricted keyed hash, not a claimed QPT PRF theorem. Its hash never needs to be inverted in the attack.

The garbled program computes both F_j and then

    H_out(t)=SHA256("CG-M" || ctx || t)

before XORing with the private 256-bit S. All three hashes are complete SHA256 Boolean circuits, not hash-oracle calls standing in for garbled computation. The exact R280 circuit module is vendored unchanged. Only nine external input-label pairs are public. There is one active label for each of 1,280 private bits (four branch seeds and S), plus the two logical constants.

Build returns a Public object and separate private test-oracle values. The attack takes ONLY Public: it has no argument containing S, private root seeds, forbidden branch keys or the complete garbler label map. The fixed program topology and mask-output wire indices are public. The test harness uses private values only to compare results against independent hashlib calculations.

## Two-evaluation full-public attack

For each local condition i:

1. Choose a full candidate w_i satisfying only C_i.
2. Compute v_i=F_i(w_i) with the public local key.
3. Evaluate the public garbled program on w_i and retain its genuine labels L_i(w_i) on the output wires of F_i.

The adversary records labels while performing its OWN public evaluation; it is not given a victim's internal representation. It then splices L_0(w_0), L_1(w_1), etc. into the suffix of the same garbled program. All fixed S labels are already public active inputs. The suffix returns

    E* = S XOR H_out(v_0 XOR ... XOR v_{m-1}).             (2)

The attacker knows every v_i, computes the hash and obtains S. In the FALSE regression w_0 has b=0 and w_1 has b=1, so this is recovery with NO possible valid witness. Two complete-vector observations suffice; no per-bit calibration, arbitrary label guessing, hash inversion or collision is required.

### Structural proposition and proof

Assume a publicly reusable classical garbling has a publicly identifiable cut carrying encodings of F_i(w); an adversary can obtain each cut vector at a locally permitted w_i and knows its ordinary value v_i. Assume the suffix computes Enc_{Mix(v_1,...,v_m)}(S), where Mix and corresponding decryption are public efficient algorithms. Then the secret is recoverable by one prefix evaluation per local condition and one suffix evaluation.

Proof: each recorded vector is a genuine encoding of v_i for that cut's fixed wires. Evaluating subsequent gate rows on those encodings computes the suffix function on the mixed values, irrespective of whether a single consistent full input would produce them together. Its result decrypts with the publicly computable Mix(v_1,...,v_m), yielding S. This is an efficient straight-line classical attack and therefore a permitted QPT attack. It uses no claim about the cryptographic strength of the unexposed PRF seeds.

The proposition is limited to an identifiable reusable cut and the stated local-key exposure. It is not an impossibility theorem for every garbling, obfuscation, SHA construction or source-specific WE. For the natural local-constraint compilation of a larger source verifier, the same argument applies whenever all local constraints are individually satisfiable and this correction structure is retained. The tested unary relation is not claimed to be a real AuxPoW exploit.

## Repairs examined and exact limits

**Nonlinear mixing:** The executed suffix already contains full SHA256. Its nonlinearity does not help because the attacker knows its entire mixed input. Replacing the mix by another public KDF or encryption function has the same issue under the proposition's premises.

**Hashing/committing the complete source:** Canonical AuxPoW and exact-wrapper/claim commitments prevent input ambiguity. They do not prevent copying intermediate labels from multiple evaluations. Unforgeable full-witness-bound tokens with a compiler that preserves that binding could change the premises, but are NOT implemented by appending H(w), adding an honest if-check or assuming a SourceOpen oracle. Their generation for arbitrary unknown future ORIGINAL certificates and their QPT joint-public proof remain missing.

**N-of-N independent capsules:** Apply the attack separately to the honest participant's public correction capsule. Honest erasure does not stop public computation. The N-of-N graph is useful only once the honest contribution's release is secure; it does not cure this encoding's flaw.

**One confirmed spend as a read-once selector:** If both branch-opening strings and label ciphertexts are available in the public preauthorized package, a recipient can copy that package and decode both labels without submitting either transaction. A ledger rejecting the second conflicting spend cannot erase the already read labels. The executable selector fixture confirms exactly that data-access property; it is not a Bitcoin or signature implementation. Withholding a branch-opening string changes the premise, but then its noninteractive source-conditioned delivery must be constructed. An online honest signer, read-once hardware, on-chain proof/trace adjudication or a renamed release assumption is not silently added. No impossibility result for every possible covenant design is asserted.

## Reproduction and security boundaries

Run Python 3.10+ with the two files in the same directory:

    python checker.py

The final checker ran twice successfully with byte-identical run1.json/run2.json. It produced 336,923 circuit nodes and 1,323,058 garbled rows. Six complete garbled outputs match hashlib; six distinct TRUE inputs unmask the same S. Honest Open rejects both selector values of the FALSE relation, while the public two-evaluation attack recovers S exactly. The selector fixture separately rejects a modeled second spend while allowing both prior data reads.

checker.py SHA256: 9af6fa8b3d1470a076c44f9676c53571eb29d9b10ff34d22705ece9770cc83e6.
Vendored r280_circuit.py SHA256: 4e34bd07570eca5a5138db3593c6e7410f29b208b8d462f5ceec51b4b117b629.
Final output SHA256: 262b0c804ed6790dcf1d9f41c4520e047e52e31d4b0935e959e220307f5156d0.

A combined command for two final runs hit its 45-second execution timeout during the second run. The first result was complete; the second was rerun separately and matched. No timed-out run is counted as successful. An earlier multi-probe version was replaced by this stronger two-vector attack; its old output files were overwritten, not claimed archived.

The checker uses reproducible test coins and inherited 128-bit garbled labels, not production randomness or calibrated PQ parameters. S is a 256-bit authorization surrogate, not an actual native signature. No Bitcoin/Syscoin consensus admission, original three-branch verifier, native PQ endpoint, quantum experiment, malicious-secure ceremony or standard-model hash proof is implemented. Full public context/checking/VK/auxiliary data does not restore secrecy of an exact payload already recovered from the public package. The single-capsule attack also needs no sibling disclosure. No keyless Build claim is made; the honest baseline builder knows its payload and seeds.

## Handoff

This synthesis materially changes the *candidate algorithm*: it removes the exponential correction table while preserving exact convergence. It does NOT establish a secure construction or satisfy the user's optimization gate. The ordinary reusable garbling realization is rejected.

The remaining obligation is a concrete classical-PPT compiler that preserves one globally consistent, fully authenticated ORIGINAL source witness throughout the hidden computation, while different valid witnesses can still yield the same frozen safe native authorization. It must withstand arbitrary public reuse, mixed partial evaluations, QPT computation, malicious setup and related capsules. Assuming a reusable witness-bound evaluator with those properties would simply assume the missing solution. No such replacement is established by this pass, and no research-completion or automation-stop claim is made.
