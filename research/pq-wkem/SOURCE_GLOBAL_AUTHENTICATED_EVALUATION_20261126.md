# Public globally authenticated evaluation trial — 2026-11-26 UTC

Status: rejected construction/repair iteration. Not a qualifying original-source release advance. No ordinary PR comment.

Continuity: actual syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, starting head 3285939cfb24f1a3969ea9fefda2d0609f7b987d. Read metadata, last three substantive discussion comments through R225, exact latest SOURCE_NONCOMMUTING_PROGRAM_TRANSPORT_20261126.md (blob aa54129492f2d3619a154c27f7c133b5d9e0f1ba), and relevant portion of SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md at that head. Re-read metadata before preservation; new path returned NOT_FOUND / 404. No new Core claims.

## 1. Selection and precise missing operation

Missing: classical offline Build must serialize public evaluation mapping every qualifying ORIGINAL future BTC/SYS/burn certificate to the same frozen native cancellation contribution S. R(x,w) denotes the complete bounded original verifier with all three independently sufficient OR branches, authenticated relevance, work, depth, claim and native-context binding. No easier relation substituted. No actual source circuit compiled here.

The closest label-splicing attack is R289: independently usable wire labels can be combined from incompatible traces. The latest noncommuting program trial additionally lost global consistency under public subgroup normalization. The mathematical change investigated here is a single hidden global algebraic authentication key shared by every wire, with independent wire masks, as in authenticated arithmetic evaluation. It attempts to couple all wire labels under one MAC rather than simply add independent lanes or hidden coefficients to an evaluator. Consider whether a public dealer-preprocessed evaluator can preserve authentication when the future prover does not have the dealer key. The immediate question is whether both legitimate input openings, needed for arbitrary future original witnesses, disclose the global authentication key. This is distinct from an invalid-trace polynomial interpolation claim in R327; it is an explicit two-label key disclosure and final-gate repair check. Once found, do not scale this family.

## 2. Serialized candidate and exact correctness

Take a bounded Boolean circuit for R with public constants, input wires, fan-out, NOT and binary Boolean gates. Every noninput wire is written once. Use a prime field F_p with p of cryptographic bit length, alpha uniform nonzero, and beta_i independent uniform in F_p for each wire i. Set t_i(b)=alpha*b+beta_i for b in {0,1}. The dealer can create all tags without a source witness. Use injective domain-separated encodings including the full context, gate identifier and ordered input tuple. No discrete-log or lattice assumption; the arithmetic is explicit.

For input wires not fixed by x, publish both (b,t_i(b)); for constants publish the appropriate single tag. For each gate i with predecessor wires j_1,...,j_k and Boolean map f_i, publish a constant-size dictionary indexed by

    H("row-index",ctx,i,t_j1(b_1),...,t_jk(b_k)).

The entry is (f_i(b),t_i(f_i(b))) XOR a hash stream under the separate "row-pad" domain with the same input. Honest evaluation can look up and decrypt precisely the matching row; dictionary collision handling must reject setup or use an unambiguous key. For output wire o publish

    D = S XOR HashStream("output",ctx,t_o(1)).

Build is polynomial in circuit size and capability length. Erase alpha and masks after producing the capsule. Open validates w or evaluates the circuit, then follows one consistent trace from w, recovering the matching tag by induction over topological order. For each qualifying w, the output tag is exactly t_o(1), so Open recovers exactly S. This is pointwise correctness of the candidate, not security. The hash pad is a concrete SHA-256 stream in the small checker only; no claim of QROM simulation or concrete SHA proof.

The input-label publication is necessary for this particular public evaluator; a source holder must be able to obtain the tag corresponding to their bit without dealer cooperation. Giving both tags does not assume access to any valid source witness. If the tag generator instead authenticates the complete source certificate before giving access to the correct tags, that is a different construction and needs an actual source-dependent cryptographic gate, not an honest-code branch.

## 3. Straight-line full-public failure, without trace splicing

Any unknown input bit with both published tags immediately gives

    alpha = t_i(1) - t_i(0) mod p.

This is exact for every setup, independent of beta_i. Run the public row traversal on any consistent *rejecting* input a. The resulting output tag t_o(0) yields

    t_o(1) = t_o(0) + alpha mod p.

Recover S directly. There is no need to combine two inconsistent internal traces, break hash security, find an original source witness, forge a native signature or inspect private dealer state. The one input a may be an all-zero malformed source encoding. The public adversary ignores the honest Open refusal and directly follows the published rows. For any complete FALSE circuit every assignment rejects; on a hard-TRUE distribution a rejecting input suffices, while an accepting input already is a certificate. Auxiliary data and other capsules can be ignored. Key disclosure is exact even with cryptographically generated random field elements and ideal hash functions.

The candidate fails already against classical adversaries, hence cannot have the required arbitrary-QPT simulation. The synthetic x AND NOT x circuit below demonstrates the failure without purporting to implement original source evidence. The general equations, not the fixture, establish the break.

## 4. Attempted repairs and why they do not yet implement a source gate

A. Do not serialize the reject output tag. This removes the direct output-flip attack but does not protect this globally authenticated gate compiler. Run any ordinary consistent trace up to the predecessors of the last gate. For every such wire j, from its one available t_j(b) compute

    t_j(v) = t_j(b) + alpha*(v-b) mod p.

For a nonconstant final gate, enumerate its at most four local input assignments. If one has output 1 and is consistent on repeated predecessor wire identities, construct its tags and decrypt the accepting final row. All such rows were generated regardless of global satisfiability. A globally true instance necessarily has such a row; an unsatisfiable circuit can have it too (the synthetic x AND NOT x has distinct last-gate predecessors). Thus even a final gate which outputs S directly on accept and an untagged reject symbol on reject does not fix the construction. This argument does not require a separate rejecting terminal tag. Pruning the accepting rows by global witness extendability is not supplied by local preprocessing. Simply granting an oracle for that pruning would change the candidate; no efficient algorithm or simulator for it is available here.

B. Try globally authenticated secret-sharing rather than reconstructible wire tags. In a conventional authenticated additive-sharing layout, for a shared value b, parties hold shares gamma_j with sum_j gamma_j=alpha*b, and shares of alpha. Giving a public evaluator every party's retained local state reveals the key directly; even if only reconstructed tag plus per-wire offset is exposed, the difference equation above applies when both bit alternatives are available. Keeping one party's state secret would block the leak but also leaves its witness-dependent messages unimplemented in the offline public evaluation. Beaver multiplication triples alone supply multiplication correctness for shared operands, not cryptographic access control on who can evaluate the final accepting bit. One-time consumption of local preprocessing is not enforceable on an ordinary copyable public capsule. This does not claim an impossibility for all MPC-based encodings: an actual public compiler that hides the necessary state while computing its responses would be a materially different mechanism.

C. Independent per-wire alpha_i prevents the above global-difference transport, but with the same complete local row dictionaries it reverts to the already-recorded unrestricted local-label splice. Reject without a new fixture. Hashing the tag before publishing it may hide the linear equation but then local transitions on the hashes are precisely reusable label tables, not an authenticated global relation. A secret nonlinear MAC or secret per-complete-trace alpha could avoid this particular equation only if the public evaluator can generate the correct authenticated wire labels without exposing the underlying authentication secret and without enabling two incompatible evaluations. If alpha(w)=H(public_seed,w), any evaluator can generate it for an arbitrary claimed trace, so it is not an authentication key. If alpha(w)=PRF(secret_seed,enc(w)), the serialized public evaluation of *source-bound* labels remains missing. Granting private evaluation, hash-domain changes, extra independent pads, or a constrained key without its jointly secure public conversion is not a repair.

The actual missing equation after these trials is a publicly executable source-dependent label-generation/translation mechanism whose full view is simulatable without the hidden terminal capability, but which returns the same frozen terminal tag for every original accepted certificate. It must not grant the ability to translate a tag from an inconsistent trace to the accepting one. No independent assumption promising that exact operation is allowed. Do not retry this global linear-MAC candidate with larger p, more shares, polynomial tags, more hash rounds or larger circuits. The conventional algebraic authentication key was never a public-evaluation primitive.

## 5. Executed minimal reproducibility check

Executed the exact Python file below locally with Python standard-library SHA-256, using a deliberately deterministic PRNG fixture (not security-grade randomness). This was a single functional synthetic falsification. No real source certificate, native signature or checking key, malicious setup, related-capsule or QPT experiment. No external literature, other repository action, Core reinspection, delegated agents or production action. R316 maturity and R225 endpoint scope unchanged. Notification gate not met.

File SHA-256: dc44b252598b60c7f68ac54b22b3abecf1bd9b52e6656c8d6df596b36771f18e

```python
import hashlib
import random

P = (1 << 127) - 1
CTX = b'PVUGC synthetic global affine MAC trial v1'

def H(domain, *args):
    fields = (CTX, domain) + args
    return hashlib.sha256(b''.join(len(v).to_bytes(4, 'big') + v for v in fields)).digest()

def enc(x):
    return x.to_bytes(16, 'big')

def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))

def build(secret):
    # Fixed reproducibility randomness; NOT cryptographic setup randomness.
    rng = random.Random(2601126)
    alpha = rng.randrange(1, P)
    beta = [rng.randrange(P) for _ in range(3)]
    tag = lambda i, b: (alpha*b + beta[i]) % P
    inputs = {b: tag(0, b) for b in (0, 1)}
    # Circuit: n = NOT x; y = AND(x,n). Both consistent assignments reject.
    gates = ((1, (0,), lambda x: 1-x), (2, (0,1), lambda x,n: x & n))
    tables = []
    for i, wires, gate in gates:
        rows = {}
        for mask in range(1 << len(wires)):
            bs = tuple((mask >> j) & 1 for j in range(len(wires)))
            ts = tuple(enc(tag(w,b)) for w,b in zip(wires,bs))
            row = H(b'row-index',enc(i),*ts)
            out = gate(*bs)
            payload = bytes([out]) + enc(tag(i,out))
            rows[row] = xor(payload,H(b'row-pad',enc(i),*ts)[:17])
        tables.append((i,wires,rows))
    capsule = (inputs,tables,xor(secret,H(b'output',enc(tag(2,1)))))
    return capsule

def walk(capsule, bit):
    inputs,tables,_ = capsule
    vals = {0:(bit,inputs[bit])}
    for i,wires,rows in tables:
        ts = tuple(enc(vals[w][1]) for w in wires)
        payload = xor(rows[H(b'row-index',enc(i),*ts)],H(b'row-pad',enc(i),*ts)[:17])
        vals[i] = (payload[0],int.from_bytes(payload[1:],'big'))
    return vals[2]

def open_honest(capsule, bit):
    b,t = walk(capsule, bit)
    return xor(capsule[2],H(b'output',enc(t))) if b == 1 else None

def recover(capsule):
    inputs,_,ciphertext = capsule
    alpha = (inputs[1]-inputs[0]) % P
    b,t = walk(capsule,0)
    target = (t + alpha*(1-b)) % P
    return xor(ciphertext,H(b'output',enc(target)))

if __name__ == '__main__':
    secret = H(b'synthetic-secret')
    C = build(secret)
    assert open_honest(C,0) is None and open_honest(C,1) is None
    assert recover(C) == secret
    print('consistent outcomes:', [walk(C,b)[0] for b in (0,1)])
    print('synthetic capability:', secret.hex())
    print('public recovery:', recover(C).hex())
```

Captured stdout:

```
consistent outcomes: [0, 0]
synthetic capability: 96367fe6bc67993118257a04243d61cb69ed17add5e4cdda1c8659b7819e96ef
public recovery: 96367fe6bc67993118257a04243d61cb69ed17add5e4cdda1c8659b7819e96ef
```

The final-gate repair analysis is algebraic, not a separately executed test.
