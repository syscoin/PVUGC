#!/usr/bin/env python3
"""Counterfactual-oracle source fixture; a model test, NOT WKEM or real AuxPoW.

Models SHA256d as one independently programmable oracle D. Uses three toy parent
certificates and a strict canonical Syscoin-tag encoding to demonstrate that
source syntax and trusted baseline can remain fixed while only fresh parent
PoW values are locally reprogrammed. Does not build an encryption or signature.
"""
import hashlib
import json
from dataclasses import dataclass


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def u32(n):
    return n.to_bytes(4, "little")


class PatchedOracle:
    def __init__(self):
        self.patches = {}
        self.calls = []

    def __call__(self, data):
        data = bytes(data)
        self.calls.append(data)
        return self.patches.get(data, sha256d(data))

    def add(self, key, output):
        assert len(output) == 32
        assert key not in self.patches
        assert sha256d(key) != output
        self.patches[key] = output


def strict_sys_tag(ancestor, ref_height):
    assert len(ancestor) == 32
    t = b"\x6a\x27sys" + ancestor + u32(ref_height)
    assert len(t) == 41
    return t


def refheight(height):
    return 10 * ((height - 6) // 10)


def expected_index(chain_id, nonce, depth):
    # This follows the AuxPoW LCG index style, not a Core invocation.
    r = nonce
    r = (r * 1103515245 + 12345) & 0xffffffff
    r = (r + chain_id) & 0xffffffff
    r = (r * 1103515245 + 12345) & 0xffffffff
    return r % (1 << depth)


def merkle_branch(leaves, ix, D):
    assert len(leaves) == 32
    branch = []
    level = leaves[:]
    while len(level) > 1:
        branch.append(level[ix ^ 1])
        level = [D(level[k] + level[k + 1]) for k in range(0, len(level), 2)]
        ix >>= 1
    return level[0], branch


def verify_branch(leaf, index, branch, D):
    v = leaf
    for sibling in branch:
        v = D((sibling + v) if index & 1 else (v + sibling))
        index >>= 1
    return v


@dataclass
class Source:
    height: int
    child: bytes
    child_prev: bytes
    child_hash: bytes
    bitcoin_header: bytes
    bitcoin_prev: bytes
    coinbase: bytes
    tag: bytes
    chain_root: bytes
    branch: list
    ix: int
    nonce: int


def build_counterfactual(D, btc_anchor, child_anchor, ancestor90, salt):
    # Both oracle worlds retain the *same* baseline and the same non-PoW bytes.
    chain_id = 16
    program = PatchedOracle()
    btc_prev = btc_anchor
    child_prev = child_anchor
    sources = []
    for k, height in enumerate((101, 102, 103)):
        assert refheight(height) == 90
        child = b"CHILD-CONTEXT" + u32(height) + u32(chain_id) + child_prev + salt + bytes([k])
        child_hash = D(child)
        nonce = 0x38494 + k
        ix = expected_index(chain_id, nonce, 5)
        leaves = [D(b"SIBLING" + salt + bytes([k, j])) for j in range(32)]
        leaves[ix] = D(b"CHILD-LEAF" + child_hash)
        root, branch = merkle_branch(leaves, ix, D)
        tag = strict_sys_tag(ancestor90, 90)
        # Two separately encoded outputs are assumed; one unique recognized tag.
        coinbase = b"CB\x02" + bytes([len(tag)]) + tag + b"\x28" + b"\xfa\xbe\x6d\x6d" + root + u32(32) + u32(nonce)
        assert coinbase.count(b"sys") == 1
        coinbase_root = D(coinbase)
        # Header layout 80 bytes, but bit target/context remain synthetic.
        header_nonce = 0xabcdee00 + k
        header = u32(0x20000000) + btc_prev + coinbase_root + u32(1731800000 + 600*k) + u32(0x1d00ffff) + u32(header_nonce)
        assert len(header) == 80
        # Choose nonce so native PoW is definitely above the toy target.
        while int.from_bytes(D(header), "big") < 2**240:
            header_nonce += 1
            header = header[:-4] + u32(header_nonce)
        patched_digest = b"\x00\x00" + D(b"PATCHED-DIGEST-DOMAIN" + header)[2:]
        assert int.from_bytes(patched_digest, "big") < 2**240
        program.add(header, patched_digest)
        sources.append(Source(height, child, child_prev, child_hash, header, btc_prev, coinbase, tag, root, branch, ix, nonce))
        btc_prev = patched_digest
        child_prev = child_hash
    return program, sources


def validate(D, xs, src, target, baseline_child101):
    prev_btc = xs["btc_anchor"]
    prev_child = xs["child_anchor"]
    ancestor90 = xs["ancestor90"]
    for i, s in enumerate(src):
        if s.height != 101 + i or s.child_prev != prev_child:
            return False, "child-link"
        if D(s.child) != s.child_hash:
            return False, "child-id"
        if s.tag != strict_sys_tag(ancestor90, refheight(s.height)):
            return False, "canonical-tag"
        if s.ix != expected_index(16, s.nonce, 5):
            return False, "slot"
        if verify_branch(D(b"CHILD-LEAF" + s.child_hash), s.ix, s.branch, D) != s.chain_root:
            return False, "child-commitment"
        if s.coinbase.count(s.tag) != 1 or b"\xfa\xbe\x6d\x6d" + s.chain_root + u32(32) + u32(s.nonce) not in s.coinbase:
            return False, "coinbase"
        if s.bitcoin_prev != prev_btc or s.bitcoin_header[4:36] != prev_btc:
            return False, "btc-link"
        if s.bitcoin_header[36:68] != D(s.coinbase):
            return False, "btc-merkle"
        actual_parent = D(s.bitcoin_header)
        if int.from_bytes(actual_parent, "big") >= target:
            return False, "btc-work"
        prev_btc = actual_parent
        prev_child = s.child_hash
    if src[0].child_hash == baseline_child101:
        return False, "no-conflict"
    if len(src) - 1 < 2:
        return False, "insufficient-toy-depth"
    return True, "toy-context-accepted"


def main():
    salt = hashlib.sha256(b"SAI114-DOMAIN-FRESH-256-ENTROPY").digest()
    xs = {
        "btc_anchor": sha256d(b"PUBLIC-BTC-ANCHOR"),
        "child_anchor": sha256d(b"PUBLIC-CHILD-HEIGHT100"),
        "ancestor90": sha256d(b"PUBLIC-CHILD-HEIGHT90"),
    }
    baseline_child101 = sha256d(b"BASELINE-CANONICAL-CHILD101" + xs["child_anchor"])
    program, sources = build_counterfactual(sha256d, xs["btc_anchor"], xs["child_anchor"], xs["ancestor90"], salt)
    # Setup may hash these public source/capsule strings. These queries are unchanged.
    setup_queries = [b"ORIGINAL-CLAIM-X" + x for x in xs.values()] + [b"CAPSULE-SESSION" + salt, b"NATIVE-VERIFY-KEYS" + salt]
    before = [sha256d(q).hex() for q in setup_queries]
    after = [program(q).hex() for q in setup_queries]
    assert before == after
    assert not (set(setup_queries) & set(program.patches))
    mock_true, reason_true = validate(program, xs, sources, 2**240, baseline_child101)
    mock_false, reason_false = validate(sha256d, xs, sources, 2**240, baseline_child101)
    assert mock_true and reason_true == "toy-context-accepted"
    assert not mock_false and reason_false == "btc-work"
    assert len(program.patches) == len(sources) == 3
    assert all(int.from_bytes(sha256d(s.bitcoin_header),"big") >= 2**240 for s in sources)
    assert all(int.from_bytes(program(s.bitcoin_header),"big") < 2**240 for s in sources)
    assert sources[0].child_hash != baseline_child101
    result = {
        "scope": "synthetic hash-oracle source fixture only; no FE, no Bitcoin/Syscoin admission, no native signing",
        "same_public_setup_hashes_after_source_patches": before == after,
        "source_oracle_changes": len(program.patches),
        "strict_tag_length": len(sources[0].tag),
        "synthetic_chain_merkle_depth": len(sources[0].branch),
        "toy_lc_depth": len(sources)-1,
        "source_certificate_with_real_sha256d": {"accept":mock_false,"reason":reason_false},
        "source_certificate_with_local_patched_SHA256d_oracle": {"accept":mock_true,"reason":reason_true},
        "parent_digest_prefixes_real": [sha256d(s.bitcoin_header).hex()[:6] for s in sources],
        "parent_digest_prefixes_counterfactual": [program(s.bitcoin_header).hex()[:6] for s in sources],
        "source_child_hashes": [s.child_hash.hex() for s in sources],
        "no_encryptor_or_oracle_simulator_implemented": True,
        "does_not_claim_concrete_sha_no_go": True,
    }
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__ == "__main__":
    main()
