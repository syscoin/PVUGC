#!/usr/bin/env python3
"""Exact finite Merkle equivocation checker. Illustrative truncated SHA-256, NOT cryptographic security."""
import hashlib
import itertools
import json


def h(bits, data):
    raw = int.from_bytes(hashlib.sha256(data).digest(), 'big') >> (256-bits)
    return raw.to_bytes((bits+7)//8, 'big')


def leaf(bits, idx, value, salt):
    return h(bits, b'L' + idx.to_bytes(2, 'big') + bytes([value]) + salt.to_bytes(4,'big'))


def parent(bits, left, right):
    return h(bits, b'P' + left + right)


def root_and_paths(bits, leaves):
    width = len(leaves)
    assert width & (width-1) == 0
    layers=[list(leaves)]
    while len(layers[-1])>1:
        x=layers[-1]
        layers.append([parent(bits,x[i],x[i+1]) for i in range(0,len(x),2)])
    paths=[]
    for j in range(width):
        k=j; path=[]
        for layer in layers[:-1]:
            path.append((k%2,layer[k^1]))
            k//=2
        paths.append(path)
    return layers[-1][0],paths


def verify(bits, commitment, idx, value, salt, path):
    acc=leaf(bits,idx,value,salt)
    for right, sibling in path:
        acc=parent(bits,sibling,acc) if right else parent(bits,acc,sibling)
    return acc==commitment


def dual_open(bits, idx):
    zeros={leaf(bits,idx,0,s):s for s in range(1<<bits)}
    for s1 in range(1<<bits):
        digest=leaf(bits,idx,1,s1)
        if digest in zeros:
            s0=zeros[digest]
            assert leaf(bits,idx,0,s0)==leaf(bits,idx,1,s1)
            return digest,s0,s1
    raise AssertionError('fixture no cross-value collision')


def test(bits, width):
    assertions=0
    pairs=[dual_open(bits,j) for j in range(width)]
    commit,paths=root_and_paths(bits,[x[0] for x in pairs])
    # The SAME root accepts ALL challenge vectors, with distinct opening bits.
    accepting=0
    for challenge in itertools.product((0,1),repeat=width):
        for j,b in enumerate(challenge):
            digest,s0,s1=pairs[j]
            salt=s0 if b==0 else s1
            assert verify(bits,commit,j,b,salt,paths[j]); assertions+=1
            assert leaf(bits,j,b,salt)==digest;assertions+=1
        accepting+=1
    assert accepting==2**width; assertions+=1
    # With one immutable bit per position, exactly one challenge is accepted.
    fixed_bits=tuple((i*7+3)&1 for i in range(width))
    fixed_salts=[pairs[i][1 if b==0 else 2] for i,b in enumerate(fixed_bits)]
    fixed_leaves=[leaf(bits,j,fixed_bits[j],fixed_salts[j]) for j in range(width)]
    fixed_root,fixed_paths=root_and_paths(bits,fixed_leaves)
    fixed_accepted=0
    for challenge in itertools.product((0,1),repeat=width):
        ok=all(challenge[j]==fixed_bits[j] and verify(bits,fixed_root,j,fixed_bits[j],fixed_salts[j],fixed_paths[j]) for j in range(width))
        fixed_accepted+=ok
    assert fixed_accepted==1; assertions+=1
    # Public checking key / contextual binding is present in leaf index, yet equivocation remains.
    for j,(digest,s0,s1) in enumerate(pairs):
        assert leaf(bits,j,0,s0)==leaf(bits,j,1,s1)==digest;assertions+=1
    return {'hash_bits':bits,'leaves':width,'challenge_vectors':2**width,
            'fixed_vector_accepted':fixed_accepted,'equivocal_vector_accepted':accepting,
            'cross_value_collision_pairs':width,'assertions':assertions,
            'root_hex':commit.hex(),
            'first_pair':{'zero_salt':pairs[0][1],'one_salt':pairs[0][2]}}


def main():
    cases=[test(8,4),test(10,8),test(12,8)]
    total=sum(x['assertions'] for x in cases)
    print(json.dumps({'experiment':'run554_merkle_equivocation','hash':'truncated SHA-256 toy',
        'cases':cases,'assertions_total':total,'conclusion':'finite existence and syntax only; not a hash or QPT security test'},sort_keys=True,indent=2))

if __name__=='__main__':main()
