#!/usr/bin/env python3
"""Restricted explicit-state hash-garbled path model. NOT original WKEM."""
from hashlib import sha256
import json,random
from collections import deque

def sh(*parts):
    h=sha256()
    for p in parts:
        if isinstance(p,str): p=p.encode()
        h.update(len(p).to_bytes(4,'little')+p)
    return h.digest()
def xor(a,b): return bytes(x^y for x,y in zip(a,b))

def compile_graph(length,allow,seed,payload):
    assert len(payload)==32
    rng=random.Random(seed)
    def rnd(): return rng.getrandbits(256).to_bytes(32,'little')
    states=[(0,'start')]+[(i,s) for i in range(1,length+1) for s in ('good','dead')]
    labels={p:rnd() for p in states}
    edges=[]
    for i in range(length):
        for s in (['start'] if i==0 else ['good','dead']):
            u=(i,s)
            for bit in (0,1):
                if i==0: nxt='good' if allow and bit==1 else 'dead'
                else: nxt=s
                v=(i+1,nxt);eid=f'{i}:{s}:{bit}:{nxt}'
                cipher=xor(labels[v],sh('edge-v1',labels[u],eid))
                edges.append({'src':f'{i}:{s}','bit':bit,'dst':f'{i+1}:{nxt}','id':eid,'cipher':cipher.hex()})
    accept=(length,'good')
    out=xor(payload,sh('release-v1',labels[accept],f'{length}:good'))
    C={'length':length,'root':'0:start','root_key':labels[(0,'start')].hex(),
       'edges':edges,'accept':f'{length}:good','out':out.hex()}
    return C

def public_open(C,bits):
    assert len(bits)==C['length']
    state=C['root']; key=bytes.fromhex(C['root_key'])
    for b in bits:
        edge=next(e for e in C['edges'] if e['src']==state and e['bit']==b)
        key=xor(bytes.fromhex(edge['cipher']),sh('edge-v1',key,edge['id']))
        state=edge['dst']
    if state!=C['accept']: return None
    return xor(bytes.fromhex(C['out']),sh('release-v1',key,state))

def bfs_public(C):
    q=deque([(C['root'],bytes.fromhex(C['root_key']), '')]);seen=set()
    while q:
        state,key,bits=q.popleft()
        if state in seen: continue
        seen.add(state)
        if state==C['accept']:
            return {'path':bits,'message':xor(bytes.fromhex(C['out']),sh('release-v1',key,state)).hex(),
                    'reachable_nodes':len(seen)}
        for e in C['edges']:
            if e['src']==state:
                k=xor(bytes.fromhex(e['cipher']),sh('edge-v1',key,e['id']))
                q.append((e['dst'],k,bits+str(e['bit'])))
    return {'path':None,'message':None,'reachable_nodes':len(seen)}

def main():
    S=sh('synthetic-safe-cancel',b'fixed-source-context')
    results={}
    for allow in [False,True]:
        C=compile_graph(6,allow,11155,S)
        outcomes={}
        for i in range(64):
            bits=f'{i:06b}'; val=public_open(C,[int(b) for b in bits]); expected=allow and bits[0]=='1'
            assert (val==S) if expected else val is None
            outcomes[bits]=val.hex() if val else None
        assert sum(v is not None for v in outcomes.values()) == (32 if allow else 0)
        bf=bfs_public(C)
        assert (bf['path'] is not None)==allow
        if allow: assert bf['message']==S.hex() and bf['path'][0]=='1'
        results['true' if allow else 'false']={
            'accepted_witness_count':sum(v is not None for v in outcomes.values()),
            'bfs':bf,'edge_count':len(C['edges']),'state_count':1+12,
            'serialized_capsule_sha256':sh(json.dumps(C,sort_keys=True)).hex()}
    # Coupled public view under a different payload: only the one accepting-node
    # output pad changes. For FALSE this is inaccessible from root, but that is
    # NOT a proof under concrete SHA or full QPT public-key access.
    C0=compile_graph(6,False,123,S)
    C1=compile_graph(6,False,123,sh('different-payload'))
    assert C0['edges']==C1['edges'] and C0['root_key']==C1['root_key'] and C0['out']!=C1['out']
    assert bfs_public(C0)['message'] is None and bfs_public(C1)['message'] is None
    results['status']='restricted explicit polynomial-state finite automata only; no original source proof or QPT theorem'
    results['sha256_payload']=S.hex()
    print(json.dumps(results,indent=2,sort_keys=True))
if __name__=='__main__':main()
