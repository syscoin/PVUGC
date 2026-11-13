#!/usr/bin/env python3
"""Exact functional boundary tests, not a cryptographic security demonstration."""
import hashlib, json, itertools, math

def H(tag,*pieces):
    h=hashlib.sha256()
    h.update(b'R169-MBVP-v1')
    h.update(len(tag).to_bytes(2,'big')); h.update(tag)
    for p in pieces:
        if isinstance(p,int): p=p.to_bytes(8,'big')
        h.update(len(p).to_bytes(4,'big'));h.update(p)
    return h.digest()

def merkle(bits):
    n=1
    while n<len(bits):n*=2
    leaf=[H(b'leaf',i, bytes([v])) for i,v in enumerate(bits)]
    leaf += [H(b'padding',i) for i in range(len(bits),n)]
    levels=[leaf]
    while len(levels[-1])>1:
        old=levels[-1]
        levels.append([H(b'node',old[i],old[i+1]) for i in range(0,len(old),2)])
    return levels

def proof(levels,i):
    return [lev[i//(1<<d)^1] for d,lev in enumerate(levels[:-1])]

def verify(root,i,b,path,n):
    if not (isinstance(b,int) and b in (0,1)) or not 0<=i<n:
        return False
    if len(path)!=(n-1).bit_length():return False
    node=H(b'leaf',i, bytes([b])); j=i
    for sib in path:
        node=H(b'node',node,sib) if j%2==0 else H(b'node',sib,node)
        j//=2
    return node==root

def trace(root,n,reads):
    # Fully public hash transcript with *same* committed Merkle root.
    state=H(b'start',root)
    for step,(i,b,path) in enumerate(reads):
        if not verify(root,i,b,path,n):return None
        state=H(b'transition',state,step,i,bytes([b]),b''.join(path))
    return state

def source_predicate(claim, anchor, child, parent_nonce, pow_bits=4):
    # Synthetic *static* source predicate, not real BTC canonical inclusion.
    h=hashlib.sha256(hashlib.sha256(b'parent'+claim+anchor+child+parent_nonce.to_bytes(2,'big')).digest()).digest()
    return (h[0]>>(8-pow_bits))==0

def run():
    checks=0
    honest=0
    false_splices=0
    false_roots=0
    valid_certificates=0
    terminal_set=set()
    max_depth=0
    # SAT formula: x_0 XOR x_1 = 1, x_2 == x_0. Each variable is repeated.
    for n in range(1,11):
        for j in range(min(1<<n, 128)):
            bits=tuple((j>>i)&1 for i in range(n))
            lev=merkle(bits); root=lev[-1][0]; max_depth=max(max_depth,len(lev)-1)
            schedule=list(range(n))+list(range(n-1,-1,-1))+[0,0]
            reads=[(i,bits[i],proof(lev,i)) for i in schedule]
            assert all(verify(root,i,v,p,n) for i,v,p in reads);checks+=len(reads)
            endpoint=trace(root,n,reads);assert endpoint is not None;checks+=1
            honest+=1
            if n>=2:
                wrong=[(i, (1-v if (step==n and i==n-1) else v), p) for step,(i,v,p) in enumerate(reads)]
                assert trace(root,n,wrong) is None;checks+=1;false_splices+=1
                other_bits=list(bits); other_bits[0]^=1
                oth=merkle(other_bits)
                wrong_root=list(reads);wrong_root[-1]=(0,1-bits[0], proof(oth,0))
                assert trace(root,n,wrong_root) is None;checks+=1;false_roots+=1
    # Explicit source fixture: two distinct valid ORIGINAL evidence strings.
    claim=b'claim-92'; anchor=b'approved-ancestor'; baseline=b'child-A'; alternate=b'child-B'
    candidates=[]; fake=[]
    for nonce in range(256):
        if source_predicate(claim,anchor,alternate,nonce):
            witness=claim+anchor+alternate+nonce.to_bytes(2,'big')
            bits=tuple((byte>>i)&1 for byte in witness for i in range(8))
            levels=merkle(bits);root=levels[-1][0]
            public_trace=trace(root,len(bits),[(i,b,proof(levels,i)) for i,b in enumerate(bits)])
            candidates.append(public_trace)
            checks+=1
        if source_predicate(claim,b'wrong-ancestor',alternate,nonce):
            fake.append(nonce)
    assert len(candidates)>=2
    valid_certificates=len(candidates)
    terminal_set=set(candidates)
    assert len(terminal_set)>1;checks+=1
    # One single frozen capsule D = K xor H_pad(d0): only first witness opens.
    K=H(b'secret-capability',b'deterministic-test-only');D=bytes(a^b for a,b in zip(K,H(b'pad',candidates[0])))
    opens=[]
    for dig in candidates:
        recovered=bytes(a^b for a,b in zip(D,H(b'pad',dig)))
        opens.append(recovered==K)
        checks+=1
    assert sum(opens)==1;checks+=1
    # A *public* Merkle proof validity check never enforces canonical-chain inclusion.
    assert len(fake)>0; checks+=1
    return {'checks':checks, 'honest_merkle_transcripts':honest,
            'mutated_leaf_rejections':false_splices,
            'cross_root_splice_rejections':false_roots,
            'max_merkle_depth':max_depth, 'toy_source_valid_work_certificates':valid_certificates,
            'distinct_valid_source_terminal_hashes':len(terminal_set),
            'single_frozen_pad_successes':sum(opens),
            'source_authenticity':'static toy PoW only, NOT best chain',
            'security_claim':'NONE: Merkle consistency is conditional on collision resistance; release compiler still absent'}
if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
