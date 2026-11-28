#!/usr/bin/env python3
"""Bounded synthetic check of malicious setup completeness, not source WE/FE."""
import hashlib, json, random
from collections import Counter

def sha(b): return hashlib.sha256(b).digest()

def bad_witness(seed: int, beacon: int, claim: bytes, domain=b'PVUGC-SETUP-RAND-v1') -> int:
    tape=sha(domain+seed.to_bytes(4,'big')+beacon.to_bytes(2,'big')+claim)
    return int.from_bytes(tape[:2], 'big') & 0xff

def one_honest_demo():
    # All 8-bit w satisfy a deliberately synthetic true relation.
    # Each tape chooses one wrong answer among all accepted witnesses.
    # Perfectly valid-looking deterministic keygen syntax does not imply
    # simultaneous all-witness correctness.
    valid=list(range(256))
    for b in range(256):
        failures=[w for w in valid if w==b]
        assert len(failures)==1
    pointwise_failures=Counter({w:1 for w in valid})
    assert all(c==1 for c in pointwise_failures.values())
    # For each fixed witness, setup failure 1/256. Yet every setup tape
    # has an accepted witness that fails. Exact finite statement.
    per_witness_failure=1/256
    universal_success=0
    # Model a committed seed before an honest public beacon.
    seed=0x5a33c01
    claim=b'public-claim-manifest-v1'
    outcomes=[bad_witness(seed, u, claim) for u in range(1<<16)]
    assert len(outcomes)==65536 and len(set(outcomes))>200
    return {"pointwise_failure_exact":per_witness_failure,"all_witness_success_exact":universal_success,
            "public_beacon_domain_size":65536,"distinct_failure_positions_under_fixed_committed_seed":len(set(outcomes)),
            "fixed_seed_and_public_beacon_do_not_establish_universal_correctness":True}

def gate_audit():
    rnd=random.Random(47042)
    def key(): return bytes(rnd.randrange(256) for _ in range(32))
    a=[key(),key()];b=[key(),key()];out=[key(),key()]
    tag=b'PVUGC-AUDIT-AND-v1'
    def enc(i,j):
        mask=sha(tag+a[i]+b[j]);return bytes(x^y for x,y in zip(mask,out[i&j]))
    rows={(i,j):enc(i,j) for i in range(2) for j in range(2)}
    def audit(table):
        return all(bytes(x^y for x,y in zip(table[i,j],sha(tag+a[i]+b[j])))==out[i&j]
            for i in range(2) for j in range(2))
    assert audit(rows)
    for i,j in rows:
        got=bytes(x^y for x,y in zip(rows[i,j],sha(tag+a[i]+b[j])))
        assert got==out[i&j]
    corrupted=dict(rows)
    corrupted[1,1]=bytes(x^y for x,y in zip(sha(tag+a[1]+b[1]),out[0]))
    assert not audit(corrupted)
    # The synthetic SOURCE policy fixes (a,b)=(0,0), so output=1
    # is unattainable. If both input labels are nevertheless public,
    # arbitrary evaluation at (1,1) computes output=1 and uncovers S.
    synthetic_secret=sha(b"PUBLIC TEST SECRET ONLY")
    frozen=bytes(x^y for x,y in zip(synthetic_secret,sha(out[1])))
    public_got_out1=bytes(x^y for x,y in zip(rows[1,1],sha(tag+a[1]+b[1])))
    premature=bytes(x^y for x,y in zip(frozen,sha(public_got_out1)))
    assert premature==synthetic_secret
    assert any(bytes(x^y for x,y in zip(corrupted[i,j],sha(tag+a[i]+b[j])))==out[i&j]
        for i,j in rows if (i,j)!=(1,1))
    return {"audited_rows":4,"all_four_honest_rows_correct":True,
        "deliberately_corrupted_row_rejected":True,
        "input_output_labels_in_clear_would_destroy_security":True,
        "zk_proof_of_audit_not_implemented":True,
        "public_two_label_false_source_bypass":premature==synthetic_secret}

if __name__=='__main__':
    result={"scope":"synthetic universal completeness and cleartext gate audit only; no source FE/WE, native signing, ZK, QPT or original witness", "pointwise_counterexample":one_honest_demo(),"local_gate_correctness":gate_audit()}
    print(json.dumps(result,sort_keys=True,indent=2))
