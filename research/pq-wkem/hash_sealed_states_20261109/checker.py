#!/usr/bin/env python3
"""HPW hash-sealed verifier-state experiment. NOT a secure generic WKEM.

Fixture seeds are deterministic for reproducibility. Production algorithms would
need independent secret randomness. This checker tests graph semantics and real
hash/Lamport operations, not QPT security or deployed Bitcoin/Syscoin validation.
"""
from __future__ import annotations
from collections import Counter, deque
from dataclasses import dataclass, replace
from itertools import product
import hashlib
import json
import random
from typing import Callable, Hashable, Optional

RUN = "HPW-HSS-20261109"
ACCEPT = ("ACCEPT",)
COUNTS: Counter[str] = Counter()


def check(condition: bool, name: str) -> None:
    COUNTS[name] += 1
    if not condition:
        raise AssertionError(name)


def encode(*parts: object) -> bytes:
    result = bytearray()
    for value in parts:
        data = value if isinstance(value, bytes) else json.dumps(
            value, sort_keys=True, separators=(",", ":")).encode()
        result += len(data).to_bytes(8, "big") + data
    return bytes(result)


def h(domain: str, *parts: object, size: int = 32) -> bytes:
    return hashlib.shake_256(encode("HPW-HSS", domain, *parts)).digest(size)


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def message(ctx: bytes) -> bytes:
    return h("native-message", ctx)


def lamport_fixture(seed: int, base_ctx: bytes) -> tuple[bytes, list[tuple[bytes, bytes]], bytes]:
    sk = [(h("test-sk", seed, i, 0), h("test-sk", seed, i, 1)) for i in range(256)]
    pk = [(h("ots-leaf", a), h("ots-leaf", b)) for a, b in sk]
    ctx = encode(base_ctx, "intended-native-vk", h("vk", b"".join(a+b for a,b in pk)))
    digest = message(ctx)
    sig = b"".join(sk[i][(digest[i // 8] >> (i % 8)) & 1] for i in range(256))
    return ctx, pk, sig


def native_verify(pk: list[tuple[bytes, bytes]], ctx: bytes, sig: Optional[bytes]) -> bool:
    if sig is None or len(sig) != 256 * 32:
        return False
    digest = message(ctx)
    return all(h("ots-leaf", sig[32*i:32*(i+1)]) ==
               pk[i][(digest[i//8] >> (i % 8)) & 1] for i in range(256))


@dataclass
class Capsule:
    ctx: bytes
    root: bytes
    terminal_check: bytes
    masked: bytes
    # A row contains an instruction and separately domain-bound transition masks.
    rows: dict[bytes, tuple[int, dict[int, bytes]]]
    pk: list[tuple[bytes, bytes]]


Expand = Callable[[Hashable], tuple[int, dict[int, Hashable]]]


def build(start: Hashable, expand: Expand, seed: int, ctx: bytes,
          sigma: bytes, pk: list[tuple[bytes, bytes]]) -> tuple[Capsule, dict]:
    """Enumerate reachable configurations; NO claim that their number is poly."""
    graph: dict[Hashable, tuple[int, dict[int, Hashable]]] = {}
    pending = deque([start])
    while pending:
        state = pending.popleft()
        if state == ACCEPT or state in graph:
            continue
        instruction, nexts = expand(state)
        graph[state] = (instruction, nexts)
        pending.extend(s for s in nexts.values() if s != ACCEPT and s not in graph)
    labels = {s: h("test-label", seed, ctx, s) for s in graph}
    labels[ACCEPT] = h("test-terminal-label", seed, ctx)
    check(len(set(labels.values())) == len(labels), "fixture_label_uniqueness")
    rows = {}
    for s, (i, nexts) in graph.items():
        label = labels[s]
        tag = h("row-tag", ctx, label)
        if tag in rows:
            raise AssertionError("fixture row-tag collision")
        rows[tag] = (i, {b: xor(labels[nxt], h("edge-pad", ctx, label, i, b))
                         for b, nxt in nexts.items()})
    accept = labels[ACCEPT]
    cap = Capsule(ctx, labels[start], h("terminal-check", ctx, accept),
                  xor(sigma, h("release", ctx, accept, size=len(sigma))), rows, pk)
    stats = {"nodes": len(graph), "edges": sum(len(x[1]) for x in graph.values()),
             "maximum_label_bytes": 32}
    return cap, stats


def release(cap: Capsule, label: bytes) -> Optional[bytes]:
    if h("terminal-check", cap.ctx, label) != cap.terminal_check:
        return None
    return xor(cap.masked, h("release", cap.ctx, label, size=len(cap.masked)))


def open_with(cap: Capsule, witness: tuple[int, ...], max_steps: int = 10000) -> Optional[bytes]:
    """Uses ONLY public capsule + supplied witness. No original predicate call."""
    label = cap.root
    for _ in range(max_steps):
        result = release(cap, label)
        if result is not None:
            return result if native_verify(cap.pk, cap.ctx, result) else None
        row = cap.rows.get(h("row-tag", cap.ctx, label))
        if row is None:
            return None
        i, choices = row
        if i >= len(witness) or witness[i] not in choices:
            return None
        b = witness[i]
        label = xor(choices[b], h("edge-pad", cap.ctx, label, i, b))
    raise RuntimeError("unbounded/cyclic fixture")


def raw_public_search(cap: Capsule) -> tuple[Optional[bytes], list[tuple[int, int]], int]:
    """No witness, private labels, graph states or Build coins are available."""
    pending = deque([(cap.root, [])])
    seen: set[bytes] = set()
    while pending:
        label, path = pending.popleft()
        if label in seen:
            continue
        seen.add(label)
        result = release(cap, label)
        if result is not None:
            return result, path, len(seen)
        row = cap.rows.get(h("row-tag", cap.ctx, label))
        if row is None:
            continue
        i, choices = row
        for b, c in sorted(choices.items()):
            nxt = xor(c, h("edge-pad", cap.ctx, label, i, b))
            pending.append((nxt, path + [(i, b)]))
    return None, [], len(seen)


def extract_consistent(path: list[tuple[int, int]], n: int) -> Optional[tuple[int, ...]]:
    assigned: dict[int, int] = {}
    for i, b in path:
        if i in assigned and assigned[i] != b:
            return None
        assigned[i] = b
    return tuple(assigned.get(i, 0) for i in range(n))


def cnf_machine(n: int, clauses: list[list[tuple[int, int]]], retain: bool) -> tuple[Hashable, Expand]:
    flat = [lit for cl in clauses for lit in cl]
    if any(len(cl) != 3 for cl in clauses) or not flat:
        raise ValueError("fixture requires nonempty 3CNF")
    last = {i: p for p, (i, _) in enumerate(flat)}
    start = (0, False, (-1,) * n if retain else ())

    def expand(state: Hashable) -> tuple[int, dict[int, Hashable]]:
        p, hit, mem = state
        i, polarity = flat[p]
        choices = {}
        for b in (0, 1):
            if retain and mem[i] not in (-1, b):
                continue
            next_hit = hit or b == polarity
            if p % 3 == 2 and not next_hit:
                continue
            if p == len(flat) - 1:
                choices[b] = ACCEPT
                continue
            memory = list(mem)
            if retain:
                memory[i] = b
                if last[i] == p:
                    memory[i] = -1
            choices[b] = (p + 1, False if p % 3 == 2 else next_hit, tuple(memory))
        return i, choices
    return start, expand


def cnf_ok(clauses: list[list[tuple[int, int]]], w: tuple[int, ...]) -> bool:
    return all(any(w[i] == b for i, b in cl) for cl in clauses)


def equality_machine(n: int) -> tuple[Hashable, Expand]:
    # Fixed read order: all first-string bits, then all second-string bits.
    def expand(state: Hashable) -> tuple[int, dict[int, Hashable]]:
        p, memory = state
        choices = {}
        for b in (0, 1):
            if p < n:
                next_mem = memory + (b,)
            else:
                if b != memory[0]:
                    continue
                next_mem = memory[1:]
            choices[b] = ACCEPT if p == 2*n - 1 else (p + 1, next_mem)
        return p, choices
    return (0, ()), expand


def prefix_machine(length: int, predicate: Callable[[tuple[int, ...]], bool]) -> tuple[Hashable, Expand]:
    def expand(state: Hashable) -> tuple[int, dict[int, Hashable]]:
        p, prefix = state
        choices = {}
        for b in (0, 1):
            nxt = prefix + (b,)
            if p + 1 < length:
                choices[b] = (p + 1, nxt)
            elif predicate(nxt):
                choices[b] = ACCEPT
        return p, choices
    return (0, ()), expand


def main() -> dict:
    rng = random.Random(167)
    rng_cases = []
    for number in range(40):
        n = 1 + number % 4
        clauses = [[(rng.randrange(n), rng.randrange(2)) for _ in range(3)]
                   for _ in range(1 + number % 5)]
        rng_cases.append((n, clauses))
    contradiction = [[(0, 1)]*3, [(0, 0)]*3]
    cases = [(1, contradiction), (2, [[(0, 1), (1, 1), (0, 1)]])] + rng_cases
    cnf_counts = Counter()
    for case, (n, clauses) in enumerate(cases):
        ctx = encode(RUN, "original-cnf", case, n, clauses, "claim-A", "branch-challenge")
        ctx, pk, sigma = lamport_fixture(case + 1000, ctx)
        start, expand = cnf_machine(n, clauses, True)
        cap, stats = build(start, expand, 2000 + case, ctx, sigma, pk)
        valid = []
        for w in product((0, 1), repeat=n):
            good = cnf_ok(clauses, w)
            opened = open_with(cap, w)
            check((opened == sigma) == good, "original_witness_exact_correctness")
            if good:
                check(native_verify(pk, ctx, opened), "actual_lamport_signature_verifies")
                valid.append(w)
            cnf_counts["assignment_tests"] += 1
        if valid:
            tampered = replace(cap, ctx=h("altered-bound-claim", cap.ctx))
            check(open_with(tampered, valid[0]) is None, "bound_context_substitution_rejected")
        got, path, visits = raw_public_search(cap)
        check((got == sigma) == bool(valid), "raw_search_matches_original_existence")
        check(visits <= stats["nodes"] + 1, "raw_search_linear_in_explicit_states")
        if got is not None:
            w = extract_consistent(path, n)
            check(w is not None and cnf_ok(clauses, w), "raw_search_extracts_original_witness")
            cnf_counts["true_formulas"] += 1
        else:
            cnf_counts["false_formulas"] += 1
        start2, expand2 = cnf_machine(n, clauses, False)
        quotient, _ = build(start2, expand2, 3000 + case, ctx, sigma, pk)
        got2, path2, _ = raw_public_search(quotient)
        check(got2 == sigma, "memory_free_quotient_can_satisfy_each_clause_locally")
        if not valid:
            check(extract_consistent(path2, n) is None, "quotient_acceptance_uses_contradictory_reads")
            check(native_verify(pk, ctx, got2), "quotient_leaks_actual_native_signature")
            cnf_counts["false_quotient_leaks"] += 1

    growth = []
    # A fixed-order state-size test, NOT a lower bound for all verifier architectures.
    for n in range(1, 11):
        growth_ctx = encode(RUN, "fixed-order-equality", n)
        growth_ctx, growth_pk, growth_sig = lamport_fixture(555+n, growth_ctx)
        start, expand = equality_machine(n)
        cap, stats = build(start, expand, 4000+n, growth_ctx, growth_sig, growth_pk)
        check(stats["nodes"] == 3*(2**n)-3, "exact_fixed_order_equality_state_count")
        check(stats["edges"] == 4*(2**n)-4, "exact_fixed_order_equality_edge_count")
        a = tuple(rng.randrange(2) for _ in range(n))
        check(open_with(cap, a+a) == growth_sig, "equality_honest_correct")
        b = (1-a[0],) + a[1:]
        check(open_with(cap, a+b) is None, "equality_inconsistent_rejected")
        got, path, visits = raw_public_search(cap)
        check(got == growth_sig, "public_bfs_unlocks_small_complete_graph")
        extracted = extract_consistent(path, 2*n)
        check(extracted is not None and extracted[:n] == extracted[n:], "bfs_equality_witness")
        growth.append({"half_witness_bits": n, "midpoint_states": 2**n, **stats})

    # Synthetic source: w=(child, anchor-selector, 7-bit parent nonce).
    # Claim binds baseline child=0; only alternative child=1 is a challenge.
    source_ctx = encode(RUN, "SYNTHETIC-NOT-SYSCOIN", "claim-B", "slot-7",
                        "anchor-A", "baseline-child-0", "capsule-fixed-context")
    source_ctx, source_pk, source_sig = lamport_fixture(7001, source_ctx)
    def source_parse(w: tuple[int, ...]) -> tuple[int, int, int]:
        nonce = sum(bit << i for i, bit in enumerate(w[2:]))
        return w[0], w[1], nonce
    def work(w: tuple[int, ...]) -> bytes:
        child, anchor, nonce = source_parse(w)
        data = encode("parent-work", source_ctx, child, anchor, nonce)
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    def predicate(w: tuple[int, ...]) -> bool:
        return len(w) == 9 and w[0] == 1 and w[1] == 1 and work(w)[0] < 16
    start, expand = prefix_machine(9, predicate)
    cap, stats = build(start, expand, 7002, source_ctx, source_sig, source_pk)
    source_valid = []
    wrong_anchor_work = 0
    duplicate_outcome_work = 0
    for w in product((0, 1), repeat=9):
        good = predicate(w)
        opened = open_with(cap, w)
        check((opened == source_sig) == good, "source_complete_evidence_release")
        if good:
            source_valid.append(w)
            check(native_verify(source_pk, source_ctx, opened), "source_native_signature_verifies")
        if work(w)[0] < 16 and w[1] == 0:
            check(opened is None, "actual_toy_work_wrong_anchor_does_not_release")
            wrong_anchor_work += 1
        if work(w)[0] < 16 and w[1] == 1 and w[0] == 0:
            check(opened is None, "same_child_new_parent_work_not_conflict")
            duplicate_outcome_work += 1
    check(len(source_valid) >= 2, "distinct_valid_source_evidence_exists")
    check(wrong_anchor_work > 0 and duplicate_outcome_work > 0, "nonvacuous_source_negative_controls")
    got, path, _ = raw_public_search(cap)
    extracted = extract_consistent(path, 9)
    check(got == source_sig and extracted is not None and predicate(extracted),
          "public_source_search_extracts_complete_toy_certificate")

    # Attempt to remove stored edges: public hash recurrence. It no longer
    # converges to a single precommitted accept label for all valid witnesses.
    final_labels = []
    for w in source_valid:
        label = h("lazy-start", source_ctx)
        for i, b in enumerate(w):
            label = h("lazy-transition", source_ctx, label, i, b)
        final_labels.append(label)
    check(len(set(final_labels)) == len(source_valid), "lazy_recurrence_distinct_accepting_labels")
    frozen = xor(source_sig, h("release", source_ctx, final_labels[0], size=len(source_sig)))
    lazy_recovered = sum(xor(frozen, h("release", source_ctx, lab, size=len(source_sig))) == source_sig
                         for lab in final_labels)
    check(lazy_recovered == 1, "one_lazy_release_record_not_every_witness_correct")

    return {"run": RUN, "status": "NO_SECURE_GENERIC_WKEM_CONSTRUCTION",
            "assertions": sum(COUNTS.values()), "checks_by_name": dict(sorted(COUNTS.items())),
            "cnf": dict(cnf_counts), "fixed_order_state_growth": growth,
            "synthetic_source": {"witness_bits": 9, "enumerated_witnesses": 512,
                "accepted_certificates": len(source_valid), "wrong_anchor_valid_work": wrong_anchor_work,
                "same_outcome_new_work": duplicate_outcome_work, "nodes": stats["nodes"],
                "edges": stats["edges"], "lazy_distinct_accept_labels": len(set(final_labels)),
                "lazy_single_record_successes": lazy_recovered},
            "limits": ["No QPT security experiment or full-joint reduction",
                       "Explicit state Build can be exponential",
                       "Source is synthetic; no Bitcoin/Syscoin inclusion or best-chain claim",
                       "Lamport fixture is not a deployed Bitcoin native endpoint",
                       "No standalone packing/performance optimization"]}


if __name__ == "__main__":
    print(json.dumps(main(), sort_keys=True, indent=2))
