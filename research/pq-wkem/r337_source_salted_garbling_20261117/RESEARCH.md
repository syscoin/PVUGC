# R337 — whole-source salt for hash-garbled gates (NONQUALIFYING)

## Provenance and selection

Read open/draft PVUGC PR #1 at actual branch head a39532a44634d689e365966bf9d56a90c07e2220 (research/pq-wkem-validation-20260918), R336 note blob 34bc1a2e973a7c621142e88f6f70bc6494e13f75 and R335 note blob 6a83fe0b185aa6fbfd953e0e4fd28a39b15f26f4. Latest top-level PR comments since November 16, 2026 returned an empty result when checked. Did NOT re-read Core #609 code, run Core tests, authenticate real source histories, or test native signatures. All executable evidence below is SYNTHETIC, not ORIGINAL challenge evidence.

**Exact new mathematical proposal:** try defeating R289's mixing of labels from inconsistent source witnesses by binding EVERY gate input label to one global source digest t(W)=SHA256(domain||x_W||W). Unlike R336's cochain pads, this is an attempted globally consistent hash-garbled verifier of the whole original source relation. The proposal would still require full contextual post-PQ AuxPoW, original three independent OR challenges, exact claim/UTXO/source/cancellation bindings, LC depth and deadline; a digest of arbitrary W is never itself evidence.

## Build/Open and the broken bridge

Let V_x(W) be the whole ORIGINAL verifier's Boolean circuit. An ordinary static Yao-style SHA-garbled circuit uses two secret fixed labels k_(i,0), k_(i,1) per primary input wire and encrypted tables for each gate. Builder encrypts ONE frozen safe capability S as CT = S XOR SHA256(cancel-domain||u_1), where u_1 is the secret true-output label. Giving one consistent input label per wire would let the evaluator compute only the honest circuit output. Source-dependent availability of those labels is the missing step.

Builder now chooses a prospective single-certificate digest t(W)=SHA256(domain||x_W||W). Ephemeral source labels are ell_(i,b)(t)=SHA256(label-domain||t||i||b). To bridge them to the prebuilt static garbled gates, it proposes the translation tau_(i,b)(t)=k_(i,b) XOR ell_(i,b)(t). An opener with W and bit b reconstructs the fixed gate label:
   k_(i,b) = tau_(i,b)(t(W)) XOR ell_(i,b)(t(W)).
This is a correctness interface, NOT a safely serialized publicly executable algorithm.

**Static-translation failure:** publishing tau at one known setup-time salt t0 fails every-witness correctness on new future salt t1. The decoded label becomes k_(i,b) XOR ell_(i,b)(t0) XOR ell_(i,b)(t1). It equals k_(i,b) only when the two random-oracle labels collide. Under a fresh independent 256-bit t1 and q_B distinct setup-time salt queries, Pr[t1 already programmed] <= q_B/2^256; this is limited to the stated independent-fresh-label model, not a theorem about actual mined source distributions or all hash-based release.

**Dynamic-translation failure:** if tau is publicly callable for ANY W—even only giving the label for the bit selected by that W—an attacker submits one arbitrary UNQUALIFIED W with bit 0 and another with bit 1, knows both t(W) and ell, and obtains BOTH fixed labels for the same primary input. Even an ideal opaque public tau oracle cannot prevent this: public inputs and outputs suffice. A reader of the serialized program might learn the labels still sooner. Both labels permit local gate assignments from inconsistent global witnesses to be mixed, exactly the R289 regression. If tau refuses to respond on unqualified ORIGINAL W, that source-dependent refusal must be enforced cryptographically in the public encoding rather than by a plaintext software if-check. Such a serialized source gate was NOT constructed here.

A public invertible, salt-dependent rekeying of static wire labels has the same issue whenever fabricated W can request both values. Publishing a private evaluator, exponential table, secret source issuer, or independent hash puzzle is not an admissible repair. A monolithic, nonlinear source-gated release may avoid the attack, but merely naming it is not an implementation or independently justified QPT primitive.

## Executed deliberately minimal FALSE test

A Python3 standard-library SHA256 Yao-garbled synthetic FALSE verifier V(x)=x AND (NOT x) was executed. Gates are an identity, a NOT, and an AND, with SHA256-pad-encrypted rows and authenticated output labels. Normal evaluations at BOTH x=0 and x=1 return only the false-output label; there is no satisfying global assignment.

A static translation bound to source digest t0 could not decrypt any gate row on t1 != t0 in the checked deterministic instance. An opaque-model dynamic translation queried with two fabricated unqualified source strings yielded fixed labels for both input bit values. The attacker then evaluated ID using x=1 and NOT using x=0, fed BOTH local true-output labels to AND, derived its TRUE output label, and recovered the EXACT 256-bit S from CT. This is an unauthorized FALSE opening using inconsistent assignments, without a valid original certificate or even an accepted synthetic one. It is already a classical attack, hence valid for the QPT adversary class. A full-public FALSE simulator for this representation cannot hide which frozen plaintext is encrypted. This experiment does not prove any generalized hash-only WE impossibility or actual ORIGINAL-source exploit.

Two invoked checker executions were byte-identical. Script SHA256: 08f3f0d7fd94a7226d2d23cba80a9b47b42af98d373ca4db5ad2ee88bdc5dad4. Both results SHA256: f63a3b077448fac9567d518ffe593681776f442e96f0e6a262c4def0a3a1f2f4. No QPT simulation, native-signature verification, Core tests or real AuxPoW source validation were executed. The script and captured JSON are committed beside this note.

## Handoff — do NOT recycle this family

The global source SHA salt gives a potential consistency label but fails to yield a **polynomial-size static hash-only public translator**. A static translator is incomplete for arbitrary future qualifying evidence; a dynamic invertible public translator leaks both labels and fails FALSE security. Do not repeat with another salt length, SHA domain, gate count or synthetic fixture unless the proposed construction changes this exact algebraic failure.

Missing ORIGINAL operation: a classical-PPT setup-time serialized public Build_inc(x_W,S) and public Open_inc(C,W) returning the SAME frozen safe native capability for EVERY fully authenticated ORIGINAL witness, while denying invalid/mixed W computational access. FALSE and hard-TRUE arbitrary QPT key recovery/native-forgery reductions, malicious setup/source-miner retention/sibling composition, strict contextual source relation and R225 native activation portability remain open. Neither a source-conditioned label map nor a joint public simulator was instantiated here.

**NONQUALIFYING.** No PR progress comment or user notification; no production/Core or automation change.
