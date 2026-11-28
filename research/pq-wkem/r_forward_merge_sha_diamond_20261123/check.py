#!/usr/bin/env python3
"""Deliberately WEAK toy 12-bit SHA256d diamond. NOT secure or original source evidence."""
import hashlib, json, math, time
BITS=12
MASK=(1<<BITS)-1

def h(x):
    return int.from_bytes(hashlib.sha256(hashlib.sha256(x).digest()).digest()[:2], 'big') >> 4

def sb(v): return v.to_bytes(2,'big')

def next_node(v, nonce): return h(b'next'+sb(v)+nonce.to_bytes(4,'little'))

def cpair(a,b,serial):
    # Deterministic birthday search, maps each starting state to a common parent.
    left={}
    for i in range(4096):
        q=next_node(a,i)
        if q not in left: left[q]=i
        # symmetrically interleave 2 candidate expansions
        other=next_node(b,i)
        if other in left: return (left[other],i,other,i+1)
    raise AssertionError('No pair collision in bounded weak toy')

def build():
    leaves=[h(b'leaf'+i.to_bytes(2,'little')) for i in range(8)]
    # ensure distinct for counting source link success probabilities
    assert len(set(leaves))==8
    level=leaves[:]
    levels=[]
    while len(level)>1:
        links=[]; nxt=[]
        for k in range(0,len(level),2):
            na,nb,parent,trials=cpair(level[k],level[k+1],len(level))
            links.append({'from':level[k],'left_nonce':na,'other_from':level[k+1],'right_nonce':nb,'to':parent,'trials':trials})
            assert next_node(level[k],na)==parent and next_node(level[k+1],nb)==parent
            nxt.append(parent)
        levels.append(links)
        level=nxt
    return leaves,levels,level[0]

def bind(label,leaves):
    # Hash-to-leaf is an extra independent puzzle, not ORIGINAL validation.
    p=h(b'src'+label)
    for q in range(1<<17):
        v=next_node(p,q)
        if v in leaves:
            return {'label':label.decode('ascii'), 'trials':q+1,'leaf':v,'link_nonce':q}
    raise AssertionError('Toy link failed unexpectedly')

def main():
    leaves,levels,root=build()
    links={}
    for level in levels:
        for e in level:
            links[e['from']]=(e['left_nonce'],e['to'])
            links[e['other_from']]=(e['right_nonce'],e['to'])
    outcomes=[]
    for label in (b'ORIGINAL-valid-synthetic',b'NOT-ORIGINAL-invalid-synthetic',b'junk-zero',b'junk-one'):
        r=bind(label,leaves)
        st=r['leaf']
        hops=0
        while st!=root:
            nonce,to=links[st]
            assert next_node(st,nonce)==to
            st=to; hops+=1
            assert hops<=3
        assert hops==3
        outcomes.append(r)
    # n=12 toy; n=256 extrapolations are mathematical expressions, not measurements.
    D=b'some secret S represented as 32 bytes!'[:32]
    pubpad=hashlib.sha256(b'pad'+sb(root)).digest()
    ct=bytes(a^b for a,b in zip(D,pubpad))
    assert bytes(a^b for a,b in zip(ct,pubpad))==D
    assert len(D)==32
    # Merely publishing H(K) instead of K does not give the opener K.
    return {'scope':'weak 12-bit hash toy; no original certificate, no security/FE',
            'digest_bits':BITS,'leaf_count':len(leaves), 'levels':len(levels),
            'build_pair_trials': [e['trials'] for level in levels for e in level],
            'root':root,'source_links':outcomes,
            'all_links_reach_public_root':True,
            'public_root_pad_immediately_recovers_secret':True,
            'independent_linking_does_not_authenticate_source':True,
            'full_256_bit_expected_link_trials_log2_with_8_leaves':253,
            'one_256_bit_collision_generic_birthday_log2':128,
            'no_private_preimage_path_derived':True}
if __name__=='__main__':print(json.dumps(main(),sort_keys=True,indent=2))
