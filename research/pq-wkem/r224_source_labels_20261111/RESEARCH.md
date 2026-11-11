# R224 — ORIGINAL-source certificate labels in public hash garbling

**Status: failed hash-only candidate; a complete classical FALSE-instance counterexample for the specified local garbling, not a practical witness-KEM, generic impossibility theorem, real source-validation test, or quantum-security proof.**

## Continuity and executed actions

- syscoin/PVUGC PR #1, open/draft on `research/pq-wkem-validation-20260918`. Observed initial head `8aee989b7cc6a3417328d0cedc420be851a9a6be`. Read R223 target-bucket note, blob `50484d122dd10e00bab27790d9294ca821dbf3b4`, and R222 edge-potential note, blob `159c1aa46799acd0000bd71d79ff7b08b82841dd`. Latest relevant ordinary PR-comment query since 2026-11-10T00:00Z returned none.
- Genuine intermediate checkpoint committed and independently read back: `749a0a2c91eb1373053d4b6d6c50e8f416a0c92a`, path `research/pq-wkem/r224_source_labels_20261111/CHECKPOINT_01.md`, Git blob `8892554376c35030bbe6369434269e0d71b818a9`.
- Ran three distinct offline Python/SHA256 checkers twice each, with byte-identical outputs and no failed assertion. No web, external literature, independent agents, original BTC/SYS implementation, native cryptographic signature, production changes, quantum simulator or source miner was used.

## Required ORIGINAL relation

The already preauthorized N-of-N cancellation path must contain one fixed claim/UTXO/path-scoped native capability; a later one-of-N notary activation and **any** qualifying original R1 greater-work BTC contradiction, R2 authenticated burn fault, or R3 AuxPoW/Syscoin claim-prefix fork/tag fault should allow any observer to recover the SAME frozen capability offline. Valid source evidence must include the actual activation, anchors, Bitcoin work/source membership, coinbase, child ancestry, correct parsing, qualified observations, light-client depth and withdrawal scope. A syntactically valid header or an independent PoW puzzle is NOT a qualifying source witness. A different Bitcoin work certificate for one pure Syscoin child is not a new child fork. No online key-label issuer is permitted.

The chosen candidate was **source-certificate-selected labels for a full ORIGINAL hash-garbled circuit**. Builder samples per-input secret labels `L[i,0]`, `L[i,1]`, garbles a deterministic source circuit, and seals the fixed native signature under the accepting output label. Honest Open needs one label corresponding to each evidence bit, with all labels globally consistent with ONE authenticated original source certificate. The issue is how a classical PPT setup supplies such labels for every future unknown certificate without also making both alternatives available to an arbitrary QPT adversary.

## Five concrete variants and exact failures

(A) Public semantic-bit labels `L[i,b]=H(context,i,b)`, or openly masked labels `E[i,b]=L[i,b] XOR H(context,i,b)`: anybody computes BOTH labels. A check executed only inside honest Open is bypassable because public garbled gate tables can be evaluated directly.

(B) Full-certificate-derived label `L[i,b]=H(context,canonical_certificate,i)`: builder cannot prepare a row for an unforeseen future work certificate. For distinct valid certificates `P0,P1`, independently hashed pads differ, so a row prepared for P0 does not yield the same frozen signature for P1. Public normalization to one known constant recovers (A); it cannot authenticate the source by itself.

(C) Private-seed pads `E[i,b]=L[i,b] XOR H(s,context,i,b)`: original independently mined BTC/SYS data do not contain private `s`, so a legitimate future challenger cannot derive input labels. Publishing `s` gives an attacker both labels before a source challenge. Retaining `s` in a source actor or fetching it online is excluded.

(D) Label delivery separately from multiple source observations: the attacker can combine locally admissible labels from different histories into a globally impossible transcript. Per-claim domain separation limits cross-claim confusion but does not fix same-claim occurrence mixing.

(E) Whole-certificate indexed row table: indexing all labels under `H(canonical full certificate)` can prevent cross-observation mixing within a known finite table, but then any unanticipated future valid certificate has no row and fails completeness. Prepublishing its accepting row and public label leaks the key before the actual future source event. This is a restricted explicit-table-family failure, not a lower bound for all possible compact nonblackbox circuits.

## Exact FALSE-instance classical attack on local hash garbling

Let the *original* Boolean predicate in the synthetic regression be `R(b) = b AND NOT(b)`. There is no original satisfying witness. Setup samples independent 256-bit wire labels `L[v,0],L[v,1]` with different permute bits. The garbled NOT gate stores

```
T_NOT[tag(L[x,b])] = L[y,1-b] XOR H_NOT(context,L[x,b]).
```

The garbled AND gate stores

```
T_AND[2 tag(L[x,a]) + tag(L[y,b])] =
  L[z,a AND b] XOR H_AND(context,L[x,a],L[y,b]).
```

It publishes `D=sigma XOR H_pad(context,L[z,1])` and `CK=H_check(context,L[z,1])`. Honest evaluation on either original assignment b=0 or b=1 gives z=0 and cannot open D.

But the adversary, possessing BOTH publicly available input labels, evaluates NOT on `L[x,0]` to derive `L[y,1]`. It then combines that label with the incompatible `L[x,1]` and evaluates AND, deriving `L[z,1]`. The public `D,CK` now reveal the precommitted `sigma` **even though there is no globally consistent witness**. It is a fully public, polynomial-time CLASSICAL attack using no SHA inversion/collision. Therefore arbitrary QPT adversaries also succeed against this exact candidate.

This is more precise than merely feeding a fake certificate to an honest verifier: the adversary evaluates real publicly posted garbled tables in an order inconsistent with any original source assignment. The regression isolates why proving the Boolean circuit correct does not make public label delivery sound.

## Repair analysis and boundary

Global full-certificate binding prevents the toy local mixing only if a future certificate's labels can be derived for that SAME source without making all candidate input labels public. With independent future mined source bytes, a builder either (i) guesses/enumerates certificate rows, (ii) supplies a secret label seed unavailable to the future source, (iii) publishes a seed admitting early recovery, or (iv) assumes a new compact cryptographic source-conditioned delivery operation.

A NEW nonblackbox SHA circuit or other hash-only source correlation might escape these **family-specific** failures. This pass does NOT prove that no such construction exists, or that a hash-only witness encryption scheme is impossible. It does show an unconditional attack if a proposal uses ordinary local garbling with both input labels independently obtainable. A Merkle root over labels authenticates bytes; it does not supply the missing source-conditioned secret openings. N-of-N preauthorization does not rescue an honestly sealed signature whose input labels are public: corrupt contributors retain their N-1 signatures and read the honest contributor's from public garbling.

## Exact executed evidence

- `checker.py` (full local only): 100 deterministic synthetic seeds, 1,100 assertions; two identical runs; source SHA256 `86cfcc98bc40cdb60608f8f7519b3746e30b8116cc854c4e0bff058bdd7ae1c9`, captured SHA256 `6a4f6be4ea57638620e958d1fa366a909c11b04fbaf12387546bfe7fb0ad3009`.
- `garbled_false_instance.py` (**published unchanged**) and `garbled_output.json` (**published unchanged**): 100 deterministic synthetic false circuits, 900 assertions; two identical executions; script SHA256 `a191e7d56673c76fef936485dc51afe73d35b38946bf715e06bd6fbff626d35f`, captured SHA256 `de18686ccf2346e343fbfb8d180ac7785b680e5eb8826858f4e7708624a74c07`. Git source blob `45cc3d42fdebc38a7686718d2da685aa8e72d365`, output blob `ef42eb92950e5fb788a110c4a696854e52639e65`. Exact published source and output match the locally executed Git hashes.
- `global_binding_repair.py` (full local only): 100 synthetic seeds, 500 assertions; two identical executions; script SHA256 `7308db34e9149bef7d932f1269a420934ad0e81e9a036a8d51d486ca1aff2e34`, captured SHA256 `3f5ba24abec904b68745a5dde024f5d137031dd3c203ded7b34c324f12e03ebd`.

These tests establish only exact functional behavior in the defined synthetic games. They are NOT a native signature test, a SHA256 standard-model theorem, a QROM theorem, a real AuxPoW source-verification test or a practical WKEM.

## Required full-public model / handoff

The adversary receives R, x_W, the complete C, checking key, native VK, activation and source contexts, source commitments, all related capsules and auxiliary data, and can run arbitrary QPT algorithms on public tables, not just honest Open. Builder and evaluation must be classical PPT, and full-public unauthorized key recovery or accepted native forgery must imply a **real qualifying ORIGINAL certificate** or independently justified PQ hash/native break. No internal representation, supplied trace or canonical witness is assumed. If random oracles are modeled, quantum access and joint simulation must be stated separately.

The unsupplied key component is:

```
Build_hash(R_cancel,x_W,sigma;coins) -> capsule
PublicSourceLabels(capsule,fully authenticated ORIGINAL future witness) -> globally consistent hidden labels
Open_hash(capsule,w) = SAME sigma for EVERY qualifying ORIGINAL witness
```

The middle API is **not instantiated**. Calling it a function, OT, a trusted source label issuer, or a private helper would merely restate the missing security problem. Source miners cannot be assumed to insert builder-specific secret input labels into existing AuxPoW tags. This pass is nonqualifying under the user's constructive reporting threshold; no ordinary PR comment. The research automation must remain enabled.
