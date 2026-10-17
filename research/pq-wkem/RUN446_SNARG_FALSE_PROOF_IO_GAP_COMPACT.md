# Run 446 — QPT argument soundness is not iO-equivalent false-instance rejection

Live draft PR: syscoin/PVUGC#1, branch `research/pq-wkem-validation-20260918`, starting SHA `6172bd8549734708878ad818a8c736f9d481f590`. Latest ordinary comment `6067040320`. This is a NEW bounded theorem, not a retry of Run 445.

## Targeted minimal release shortcut

A public NP computation yields an off-chain succinct proof `pi`; a compact protected circuit `G_{x,K}(pi)` outputs the SAME native signing capability K on an accepted proof and bottom otherwise. The intended Bitcoin endpoint verifies only an ordinary branch signature. Witness privacy is unnecessary. The proposed security proof replaces `G_{x,K}` by a constant-bottom program on false ORIGINAL statements using QPT iO.

**New barrier:** computationally sound succinct proof verification does NOT imply this required **extensional circuit equivalence**. A false statement can have an accepting proof that is hard for all QPT outsiders to find. This invalidates the specific iO-to-zero hybrid; it does NOT prove that the actual protected program leaks K.

## Exact counterexample compiler

Let `Pi0=(S0,P0,V0)` be any classical PPT, complete, QPT computationally sound public-verifier argument for an NP relation R, with false-proof advantage eps0. Let `f:{0,1}^lambda->{0,1}^m` be QPT one-way with inversion advantage epsf on `s` sampled uniformly. Per-instance classical setup samples independent s and publishes `crs*=(crs0,y=f(s))` while the honest setup erases s. Define a proof as `(b,p)` and

`V*(crs*,x,(b,p)) = (b=0 AND V0(crs0,x,p)) OR (b=1 AND f(p)=y)`.

Honest proofs use the b=0 branch. Completeness and succinctness survive (one tag bit plus an O(lambda)-bit alternate proof, extra poly(lambda) verification).

**QPT computational soundness:** any accepting false proof with b=0 breaks Pi0; with b=1 it inverts f. For public auxiliary information simulatable from the challenge distributions, `Adv_false(Pi*) <= eps0 + epsf`. The reductions are straight-line, no quantum rewinding or QROM programming. Public f and V* permit coherent evaluation. Independent polynomially many capsules admit the corresponding union bound, subject to the same auxiliary-input assumptions. The claim does NOT hold if setup preimage s is retained or auxiliary quantum advice is correlated with s.

**Extensional inequivalence:** for every sampled y=f(s), even when x has NO ORIGINAL witness, `V*(x,(1,s))=1`. Thus `G_{x,K}(1,s)=K != bottom=Z(1,s)` for K != bottom. The circuits are not functionally equivalent. Classical or QPT iO on equivalent circuits cannot justify this hybrid. Standard QPT soundness does not rule out mathematical false accepting inputs.

## Release/frontier ramifications

- Source-bound proof-gated release would be smaller than protecting the entire original NP verifier, but the proposed iO proof requires **all-input** false-instance nonacceptance, not just computationally unreachable invalid proofs.
- Run 259's **statistical, high-codimension global folding** has an all-invalid-representation-excluded good-setup event. That is a *possible equivalence premise*, not a small release construction: the protected circuit must still bind every supplied residual to the complete ORIGINAL representation. Its SIS compression provides QPT hardness for invalid accepted representations, but not extensional nonexistence.
- A compact verifier with only computational soundness could still be useful under an independently established differing-input/obfuscation security theorem. No such theorem is constructed or assumed here. Labeling it “local mixing” would be circular.
- Run 259's extraction accepts complete source representations only. An arbitrary native signature or the planted proof (1,s) does not become a valid ORIGINAL representation.
- One honest N-of-N setup/erasure must explicitly exclude planted bypasses. The checker illustrates a setup party retaining s and signing on a false ORIGINAL instance. This is **not** an outside attack when s is honestly erased and f is QPT one-way.

## Attack/QPT ledger

Honest setup/prover/evaluator: classical PPT. External adversary: arbitrary QPT with all public CRS, x, relation/UTXO/branch context, public native checking key, multiple independently generated capsules, and coherent access to public evaluation. QPT soundness depends on exact base argument and f assumptions, and on simulatable auxiliary advice; no full QPT witness-KEM security follows. Failure concerns public chosen-proof evaluation (taxonomy 5), malicious retained setup seeds (6), and the checking-key/ORIGINAL-extraction interface (8). Toy checker also rejects cross-UTXO proof reuse (7). No seam, gauge, fingerprint, or genuinely quantum-only attack is claimed.

**Executed validation:** exact published JS checker, deterministic 256-element permutation (deliberately NOT one-way), four contexts, exhaustive proof enumeration, three distinct valid ORIGINAL witnesses recovering the same toy capability, false ORIGINAL statements with one accepting non-ORIGINAL proof, and cross-context rejection. The extended independent local Python diagnostic uses four SHA-256 toy instances and Ed25519 **NON-PQ** signatures; 49,256 assertions. Neither implementation tests QPT hardness, implements iO, or constructs a practical WKEM.

**Literature boundary:** iO requires exact equivalent circuit behavior; see Garg–Gentry–Halevi–Raykova–Sahai–Waters, SIAM J. Comput. 2016, https://doi.org/10.1137/14095772X . Canetti–Luo–Zhang, CRYPTO 2026, https://doi.org/10.1007/978-3-032-35367-2_18 is NOT refuted; its merged full proofs were not audited. Live exact dependencies: CLZ assessment Git blob `c19d9d9cd515140e3ce62eac960cd548c0add622`; Run444 blob `50eb9ccf38fa7336ea22a9cee199e3b82d6be33d`; Run259 source note blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`.

**Checkpoint:** no practical post-quantum WKEM; false-instance native forgery hiding, true-instance forgery-to-ORIGINAL extraction, malicious setup, coherent multiple-capsule security and concrete resources remain UNPROVED. Draft stays unmerged; no production modifications.
