#!/usr/bin/env python3
"""R172 hash-state experiments; toy classical checks, NOT a secure WKEM."""
import hashlib,itertools,json
from collections import deque

def h(*fields):
    b=bytearray(b'R172/compact')
    for f in fields:
        v=f if isinstance(f,bytes) else str(f).encode()
        b+=len(v).to_bytes(4,'big')+v
    return hashlib.sha256(b).digest()

def xor(a,b): return bytes(x^y for x,y in zip(a,b))
def sat(cnf, bits): return all(any(bits[abs(l)-1]==int(l>0) for l in c) for c in cnf)

def graph(n, cnf, seed):
    labels={(i,p):h(seed,i,bytes(p)) for i in range(n+1)
            for p in itertools.product((0,1),repeat=i)}
    key=h('frozen',seed); rows={}
    for (i,p),label in labels.items():
        if i==n:
            if sat(cnf,p):
                rows[h('tag',label,'accept')]=[('accept',xor(key,h('pad',label,'accept')))]
            continue
        for bit in (0,1):
            child=labels[(i+1,p+(bit,))]
            rows[h('tag',label,i,bit)]=[(bit,xor(child,h('pad',label,i,bit)))]
    return labels[(0,())],rows,key,len(labels)

def bfs(root,rows,n):
    q=deque([(0,(),root)]); seen=set()
    while q:
        i,bits,label=q.popleft()
        if label in seen: continue
        seen.add(label)
        if i==n:
            for _,ct in rows.get(h('tag',label,'accept'),[]):
                return xor(ct,h('pad',label,'accept')),bits,len(seen)
            continue
        for bit in (0,1):
            for _,ct in rows.get(h('tag',label,i,bit),[]):
                q.append((i+1,bits+(bit,),xor(ct,h('pad',label,i,bit))))
    return None,None,len(seen)

def check():
    results=[]
    for n in range(1,10):
        words=list(itertools.product((0,1),repeat=n))
        # Distinguishable suffix: each first-half prefix accepts only matching suffix.
        assert len({tuple(a==b for b in words) for a in words})==2**n
        def f(p): return sum(bit<<i for i,bit in enumerate(p))
        assert len({f(w) for w in words})==2**n
        for a in words:
            for b in words: assert (f(a)-f(b)==0)==(a==b)
        results.append([n,2**n])
    # A public label for the accepting accumulator (=0) leaks the capability.
    key=h('frozen','public-fingerprint')
    ct=xor(key,h('accept','fingerprint=0'))
    assert xor(ct,h('accept','fingerprint=0'))==key
    # Hash-sealed graph is publicly traversable without a source witness.
    cases=[('true',3,[[1],[2],[3]]),('false',1,[[1],[-1]]),
           ('multi',5,[[1,2],[-2,3],[4,-5]])]
    reports=[]
    for name,n,cnf in cases:
        root,rows,k,nodes=graph(n,cnf,name)
        opened,w,visited=bfs(root,rows,n)
        expected=any(sat(cnf,a) for a in itertools.product((0,1),repeat=n))
        assert bool(opened)==expected
        if opened: assert opened==k and sat(cnf,w)
        assert nodes==2**(n+1)-1
        reports.append({'case':name,'satisfiable':expected,'nodes':nodes,
                        'BFS_recovered_key_without_witness':bool(opened),
                        'BFS_extracted_valid_witness':list(w) if w else None,
                        'visited':visited})
    return {'security':'NONE; research-only toy',
            'prefix_equivalence_classes':results,
            'total_prefix_classes':sum(z[1] for z in results),
            'public_terminal_mask_bypassed':True,
            'explicit_graph_cases':reports}

if __name__=='__main__': print(json.dumps(check(),sort_keys=True,indent=2))
