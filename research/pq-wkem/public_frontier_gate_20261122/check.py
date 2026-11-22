#!/usr/bin/env python3
"""Small public hash-garbled deterministic automaton.
Synthetic fixture. Not a Bitcoin/Syscoin certificate or source witness-KEM.
PUBLIC seed purely for reproducible tests, not real secret randomness.
"""
import hashlib,json
from collections import deque

H=lambda b:hashlib.sha256(b).digest()
X=lambda a,b:bytes(x^y for x,y in zip(a,b))

def label(seed, i,q):return H(b'LABEL'+seed+i.to_bytes(4,'little')+q.to_bytes(4,'little'))
def tag(i,k):return H(b'TAG'+i.to_bytes(4,'little')+k).hex()
def pad(i,b,k):return H(b'PAD'+i.to_bytes(4,'little')+bytes([b])+k)
def endtag(k):return H(b'ENDTAG'+k).hex()
def endpad(k):return H(b'ENDPAD'+k)

def build(n, states, initial, transition, accept, s, seed):
    assert len(s)==32
    table=[]
    for i in range(n):
        level={}
        for q in range(states):
            k=label(seed,i,q)
            level[tag(i,k)]=[X(label(seed,i+1,transition(q,b)),pad(i,b,k)).hex() for b in (0,1)]
        table.append(dict(sorted(level.items())))
    end={endtag(label(seed,n,q)):X(s,endpad(label(seed,n,q))).hex() for q in accept}
    return {'n':n,'initial':label(seed,0,initial).hex(),'table':table,'end':end}

def open_full(c, bits):
    if len(bits)!=c['n']:return None
    k=bytes.fromhex(c['initial'])
    for i,b in enumerate(bits):
        row=c['table'][i].get(tag(i,k))
        if row is None:return None
        k=X(bytes.fromhex(row[int(b)]),pad(i,int(b),k))
    v=c['end'].get(endtag(k))
    return None if v is None else X(bytes.fromhex(v),endpad(k))

def public_bfs(c):
    """Only public capsule bytes; explores both bits, merges equivalent labels."""
    level={bytes.fromhex(c['initial']):''}; counts=[1]
    for i in range(c['n']):
        nxt={}
        for k,prefix in level.items():
            row=c['table'][i].get(tag(i,k))
            if row is None:continue
            for b in (0,1):
                k2=X(bytes.fromhex(row[b]),pad(i,b,k))
                nxt.setdefault(k2,prefix+str(b))
        level=nxt; counts.append(len(level))
    for k,w in level.items():
        v=c['end'].get(endtag(k))
        if v is not None:return {'witness':w,'secret':X(bytes.fromhex(v),endpad(k)).hex(),'frontier':counts}
    return {'witness':None,'secret':None,'frontier':counts}

def check_words(bits, q0, trans, accept):
    q=q0
    for b in bits:q=trans(q,int(b))
    return q in accept

def main():
    seed=H(b'PUBLIC SYNTHETIC RNG SEED - NOT SECURE')
    S=H(b'PUBLIC S - NOT ACTUAL CLAIM SIGNATURE')
    def t(q,b):return (q & 2) | b | ((q&1)^b)*0 # state= seen-one flag bit1, parity bit0? use correct below
    # states q=(seen_one<<1)|parity; next seen |= bit, parity ^= bit
    t=lambda q,b: 2*(((q>>1)&1)|b) + ((q&1)^b)
    n=10
    c=build(n,4,0,t,{2,3},S,seed)
    yes=no=0
    for z in range(1<<n):
        bits=format(z,f'0{n}b')
        v=open_full(c,bits)
        expected=check_words(bits,0,t,{2,3})
        assert (v==S)==expected
        if expected: yes+=1
        else:no+=1
    assert yes==(1<<n)-1 and no==1
    # Larger fixture: public BFS needs O(n * reachable states) not 2^n words.
    long=build(24,4,0,t,{2,3},S,seed)
    attack=public_bfs(long)
    assert attack['secret']==S.hex()
    assert check_words(attack['witness'],0,t,{2,3})
    assert max(attack['frontier'])<=4
    # Explicit FALSE: accept state unreachable from an always-zero machine.
    dead=build(24,4,0,lambda q,b:0,{3},S,seed)
    none=public_bfs(dead)
    assert none['witness'] is None
    # We do not interpret negative BFS as cryptographic secrecy against arbitrary capsule processing.
    print(json.dumps({'scope':'synthetic public serialized automaton; no original source or QPT security',
       'test_seed_public':True,'all_valid_small_open_same_secret':yes,'invalid_small_cannot_prescribed_open':no,
       'long_input_length':24,'long_public_table_rows':sum(len(x) for x in long['table']),
       'public_bfs_total_frontier_states':sum(attack['frontier']),
       'public_bfs_max_frontier':max(attack['frontier']),
       'public_bfs_found_valid_witness':attack['witness'],
       'public_bfs_recovers_exact_s':attack['secret']==S.hex(),
       'false_fixture_reachable_accept':none['witness'] is not None,
       'qpt_full_public_security_proved':False},sort_keys=True,indent=2))
if __name__=='__main__':main()
