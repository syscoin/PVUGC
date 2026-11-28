#!/usr/bin/env python3
"""R170: reproducible finite oracle-transplant/coupling checks.

NOT a witness-KEM implementation or proof of QPT cryptographic security.
Tests oracle simulation and the low-query indistinguishability premise.
"""
import hashlib
import json
import random
from collections import Counter


def H(x):
    return hashlib.sha256(x).digest()


def randfunc(seed, n):
    # Domain/range both n bits; lazy pseudorandom table only for synthetic tests.
    mask=(1<<n)-1
    def f(z):
        assert 0<=z<(1<<n)
        return int.from_bytes(H(b'R170_f'+seed.to_bytes(4,'big')+z.to_bytes(4,'big')), 'big') & mask
    return f


def build_trace(f,y,K,n,q):
    # NOT a protected encryption; isolates exactly the generator oracle queries.
    state = H(b'R170_start'+y.to_bytes(4,'big')+K.to_bytes(4,'big'))
    queries=[]
    for i in range(q):
        z=int.from_bytes(state[:4],'big') % (1<<n)
        queries.append(z)
        v=f(z)
        state=H(b'R170_step'+state+v.to_bytes(4,'big')+i.to_bytes(4,'big'))
    return state, queries


def finite_coupling():
    n=12; q=32; trials=2400; masks=(1<<n)-1
    changed=0; hit=0; fake_success=0; z_is_genuine=0
    q_unique_total=0
    for i in range(trials):
        f=randfunc(11072000+i,n)
        s=int.from_bytes(H(b'R170_true'+i.to_bytes(4,'big'))[:4],'big') & masks
        y=f(s)
        z=int.from_bytes(H(b'R170_fake'+i.to_bytes(4,'big'))[:4],'big') & masks
        K=int.from_bytes(H(b'R170_key'+i.to_bytes(4,'big'))[:4],'big')
        def fz(x): return y if x==z else f(x)
        before,queries=build_trace(f,y,K,n,q)
        after,_=build_trace(fz,y,K,n,q)
        h=(z in set(queries))
        hit+=h;changed+=before!=after
        fake_success+=(fz(z)==y and fz(s)==y if z!=s else fz(z)==y)
        z_is_genuine+=(f(z)==y)
        q_unique_total+=len(set(queries))
        assert (before==after) if not h else True
        assert f(s)==y and fz(z)==y
    # A uniform independent z hits B's query set with exact probability |Q|/2^n.
    expected=q_unique_total/(1<<n)
    assert hit<q*trials // (1<<n)*4+40
    return {"n_bits":n,"q_per_builder":q,"trials":trials,"queried_fake_address":hit,"expected_hits":round(expected,4),"changed_builder_transcript":changed,"fake_is_original_valid":z_is_genuine,"fake_is_modified_oracle_valid":fake_success,"query_union_total":q_unique_total,"finite_only":True}


def quantum_xor_oracle():
    # Exact basis-state equality implies same unitary on arbitrary superposition.
    n=3;m=3;mask=(1<<m)-1;counter=0
    for seed in range(17):
        f=randfunc(seed,n)
        z=(seed*3)% (1<<n)
        y=(seed*5+1)&mask
        delta=f(z)^y
        def fz(x):return y if x==z else f(x)
        def og(x,t):return x,t^f(x)
        def of(x,t):return x,t^fz(x)
        def correction(x,t):return x,(t^delta) if x==z else t
        for x in range(1<<n):
            for t in range(1<<m):
                assert of(x,t)==correction(*og(x,t))
                counter+=1
        # A reversible XOR oracle implementation, not access to an altered oracle.
    assert counter==17*64
    return {"address_bits":n,"output_bits":m,"oracles_checked":17,"basis_pairs":counter,"coherent_unitary_identity":True}


def exponential_table_control():
    # Exponential Build intentionally queries ALL domain points and therefore
    # violates the condition for efficient oracle transplant. In the original
    # oracle, an unseen false z has no record; under fz, a new record is needed.
    n=10; trials=20; misses=0; queries=0; true_counts=[]
    for seed in range(trials):
        f=randfunc(252000+seed,n)
        s=(seed*293+13)%(1<<n)
        y=f(s)
        entries=set()
        for w in range(1<<n):
            queries+=1
            if f(w)==y:entries.add(w)
        false_candidates=[z for z in range(1<<n) if z not in entries]
        z=false_candidates[seed%len(false_candidates)]
        assert f(z)!=y and z not in entries
        def fz(w):return y if w==z else f(w)
        assert fz(z)==y
        # Recomputed Build under new oracle WOULD include z, but old C does not.
        misses+=1
        true_counts.append(len(entries))
    return {"n_bits":n,"trials":trials,"all_domain_queries":queries,"new_valid_fake_not_in_old_table":misses,"max_old_valid_witnesses":max(true_counts),"requires_exponential_build":True}


def main():
    out={"study":"R170 oracle transplant; no WKEM security claim", "coupling":finite_coupling(),"coherent_oracle":quantum_xor_oracle(),"negative_control":exponential_table_control(),"interpretation":"Finite tests check coupling/oracle correction only; no generic-NP Build, QPT hardness or real Syscoin/BTC validation"}
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=='__main__':main()
