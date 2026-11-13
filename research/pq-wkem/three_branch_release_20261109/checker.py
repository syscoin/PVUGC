#!/usr/bin/env python3
"""Offline policy and authenticated-nonmembership checks, NOT witness encryption.

The Merkle primitive is executable. BTC/SYS qualification below is deliberately
an abstract Boolean input; no production header/DAA/AuxPoW validator is claimed.
No release gate, native signature or QPT security experiment is implemented.
"""
from __future__ import annotations
import hashlib
import itertools
import json
from collections import Counter
from typing import Optional

checks: Counter[str] = Counter()

def ck(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    checks[label] += 1

def h(domain: bytes, *parts: bytes) -> bytes:
    data = len(domain).to_bytes(4, 'big') + domain
    for part in parts:
        data += len(part).to_bytes(4, 'big') + part
    return hashlib.sha256(data).digest()

def leaf(key: int, value: Optional[bytes]) -> bytes:
    if value is None:
        return h(b'tri-cancel/empty')
    return h(b'tri-cancel/occupied', key.to_bytes(32, 'big'), value)

def node(left: bytes, right: bytes) -> bytes:
    return h(b'tri-cancel/node', left, right)

class TinySparseMap:
    """Eight-bit toy keyspace; production sparse-tree depth is NOT asserted."""
    def __init__(self, entries: dict[int, bytes], depth: int = 8):
        self.depth = depth
        self.entries = dict(entries)
        if any(k < 0 or k >= 1 << depth for k in entries):
            raise ValueError('key outside fixed tree')
        self.levels = [[leaf(k, entries.get(k)) for k in range(1 << depth)]]
        for _ in range(depth):
            old = self.levels[-1]
            self.levels.append([node(old[i], old[i+1]) for i in range(0, len(old), 2)])
        self.root = self.levels[-1][0]
    def proof(self, key: int) -> list[bytes]:
        out = []
        for level in self.levels[:-1]:
            out.append(level[key ^ 1])
            key >>= 1
        return out

def verify(root: bytes, key: int, value: Optional[bytes], path: list[bytes], depth: int=8) -> bool:
    if not 0 <= key < 1 << depth or len(path) != depth:
        return False
    current = leaf(key, value)
    for sibling in path:
        if len(sibling) != 32:
            return False
        current = node(sibling, current) if key & 1 else node(current, sibling)
        key >>= 1
    return current == root

def work(target: int) -> int:
    if not 0 < target < (1 << 256):
        raise ValueError('invalid target')
    return (1 << 256) // (target + 1)

def btc_branch(qualified: bool, same_anchor: bool, conflicts: bool, candidate: int, proposed: int) -> bool:
    # ABSTRACT policy composition; qualified must be supplied by the actual
    # verifier, not by an adversary-controlled flag in a production protocol.
    return qualified and same_anchor and conflicts and candidate > proposed

def sys_branch(qualified: bool, same_reference_height: bool,
               baseline_hash: bytes, candidate_hash: bytes,
               descendants: int, required: int) -> bool:
    return (qualified and same_reference_height and baseline_hash != candidate_hash
            and descendants >= required)

def selected(j: int, bits: tuple[bool, bool, bool]) -> bool:
    return j in (1, 2, 3) and bits[j-1]

def main() -> dict:
    # Sparse burn registry is a PROPOSED authenticated representation, not a
    # claim about what current Syscoin headers commit to.
    burn = json.dumps({'claim':'W','amount':9,'recipient':'script-A','reserve':'V'},
                      sort_keys=True, separators=(',', ':')).encode()
    states = [{}, {37:burn}, {37:burn, 100:b'other', 255:b'last'}]
    for entries in states:
        tree = TinySparseMap(entries)
        for key in range(256):
            value = entries.get(key)
            path = tree.proof(key)
            ck(verify(tree.root, key, value, path), 'membership_or_absence_path')
            ck(verify(tree.root, key, None, path) == (key not in entries),
               'absence_matches_committed_state')
            ck(not verify(tree.root, key, b'forged value', path), 'wrong_leaf_value_rejected')
            ck(not verify(tree.root, key, value, path[:-1]), 'incomplete_path_rejected')
    tree = TinySparseMap({37:burn})
    absent_tree = TinySparseMap({})
    ck(not verify(tree.root, 37, None, absent_tree.proof(37)), 'substituted_root_proof_rejected')
    ck(not verify(tree.root, 37, None, tree.proof(36)), 'neighbor_absence_not_target_absence')
    changed = burn.replace(b'"amount":9', b'"amount":8')
    ck(not verify(tree.root, 37, changed, tree.proof(37)), 'amount_binding')
    changed = burn.replace(b'script-A', b'script-B')
    ck(not verify(tree.root, 37, changed, tree.proof(37)), 'recipient_binding')

    # Exact target-derived work, not block count or observed hash luck.
    easy = (1 << 252)-1
    hard = (1 << 248)-1
    ck(work(easy)==16 and work(hard)==256, 'exact_work_formula')
    longer = 3 * work(easy)
    shorter = 2 * work(hard)
    ck(longer < shorter, 'longer_can_have_less_work')
    ck(not btc_branch(True, True, True, longer, shorter), 'longer_lower_work_rejected')
    ck(btc_branch(True, True, True, shorter, longer), 'shorter_higher_work_allowed')
    ck(not btc_branch(True, True, False, shorter, longer), 'ordinary_extension_not_conflict')
    ck(not btc_branch(False, True, True, shorter, longer), 'unauthenticated_work_rejected')
    ck(not btc_branch(True, False, True, shorter, longer), 'different_anchor_rejected')
    ck(not btc_branch(True, True, True, shorter, shorter), 'equal_work_not_greater')
    for k in (1, 3, 7):
        a, b = h(b'child-A'), h(b'child-B')
        ck(not sys_branch(True,True,a,b,k-1,k), 'insufficient_fork_depth_rejected')
        ck(sys_branch(True,True,a,b,k,k), 'fork_depth_boundary_accepted')
        ck(not sys_branch(True,True,a,a,k+5,k), 'same_child_work_variants_not_conflict')
        ck(not sys_branch(False,True,a,b,k,k), 'unqualified_sys_fork_rejected')

    # AND over participant contributions, OR over challenge branches.
    # Boolean composition ONLY: no private release helper or fake gate used.
    for truths in itertools.product((False, True), repeat=3):
        for j in range(1,4):
            ck(selected(j, truths)==truths[j-1], 'selected_branch_only')
        ck(not selected(0,truths) and not selected(4,truths), 'selector_domain')
        for n in (1,2,3,4):
            ck(all(any(truths) for _ in range(n))==any(truths), 'one_challenge_suffices_all_honest')
        for held in itertools.product((False,True),repeat=3):
            # Corrupt participants may reveal their own contribution early.
            available = [held[i] or any(truths) for i in range(3)]
            ck(all(available)==(all(held) or any(truths)), 'n_of_n_early_retention_boundary')
    ck(any((True,False,False)) and not all((True,False,False)), 'and_of_challenges_is_wrong')

    # Hashing distinct accepting transcripts does not give a common frozen key.
    transcript1 = b'branch=1;certificate=A'
    transcript2 = b'branch=3;certificate=B'
    ck(h(b'proof-derived-key',transcript1)!=h(b'proof-derived-key',transcript2),
       'proof_hashes_are_not_common_capability')

    return {'run':'TRI-CANCEL-20261109', 'assertions':sum(checks.values()),
            'groups':dict(sorted(checks.items())),
            'scope':'Merkle-path and policy algebra only; NOT a key-release implementation',
            'not_implemented':['production BTC/SYS qualification','challenge-conditioned release',
              'native signatures','QPT security experiment','malicious N-of-N setup'],
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True,indent=2))
