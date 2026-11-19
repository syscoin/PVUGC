#!/usr/bin/env python3
"""Synthetic directed SHA edge-label gate. NOT original Bitcoin/Syscoin WE."""
import hashlib, json, collections
D=b'R380-directed-key-edge-v1'
def H(x): return hashlib.sha256(x).digest()
def X(a,b): return bytes(x^y for x,y in zip(a,b))
def K(label):return H(D+b':key:'+label.encode())
def gate(u,v,ku):return H(D+b':edge:'+u.encode()+b'>'+v.encode()+b':'+ku)
def make(edges, small=False):
    keys={v:K(v) for uv in edges for v in uv}
    keys.update({'s':K('s'),'t':K('t')})
    if small:
        keys['b']=bytes([K('tiny')[0]&15,K('tiny')[1]])+bytes(30)
    secret=H(D+b':cancel-capability')
    return {'edges':edges,'pub':{u+'>'+v:X(keys[v],gate(u,v,keys[u])) for u,v in edges},
            'root':keys['s'],'D':X(secret,keys['t'])},keys,secret

def open_graph(C):
    seen={'s':C['root']};paths={'s':['s']};todo=collections.deque(['s'])
    while todo:
        u=todo.popleft()
        for a,b in C['edges']:
            if a!=u:continue
            kv=X(C['pub'][a+'>'+b],gate(a,b,seen[u]))
            if b in seen:
                assert seen[b]==kv
            else:
                seen[b]=kv;paths[b]=paths[u]+[b];todo.append(b)
    return (X(C['D'],seen['t']) if 't' in seen else None),paths

def xor_reverse_break(C,keys):
    # Bad predecessor scheme E(u,v)=key_u XOR key_v is reversible in both directions
    reversible={u+'>'+v:X(keys[u],keys[v]) for u,v in C['edges']}
    seen={'s':keys['s']};todo=collections.deque(['s'])
    while todo:
        u=todo.popleft()
        for a,b in C['edges']:
            if u not in [a,b]: continue
            v=b if u==a else a
            if v not in seen:
                seen[v]=X(seen[u],reversible[a+'>'+b]);todo.append(v)
    return X(C['D'],seen['t']) if 't' in seen else None

def main():
    good=[('s','a'),('s','b'),('a','t'),('b','t')]
    C,keys,secret=make(good)
    recovered,paths=open_graph(C)
    assert recovered==secret and paths['t'] in [['s','a','t'],['s','b','t']]
    for path in (['s','a','t'],['s','b','t']):
        val=C['root']
        for u,v in zip(path,path[1:]):val=X(C['pub'][u+'>'+v],gate(u,v,val))
        assert X(C['D'],val)==secret
    # Acyclic directed graph: undirected s-a-b-t connected, directed s-to-t absent.
    bad=[('s','a'),('b','a'),('b','t')]
    F,fkeys,fsecret=make(bad,small=True)
    assert open_graph(F)[0] is None
    assert xor_reverse_break(F,fkeys)==fsecret
    # Explicit attack on 12-bit toy SHA key of b via public predecessor a.
    known_a=X(F['pub']['s>a'],gate('s','a',F['root']))
    target_ba=X(F['pub']['b>a'],known_a) # H(edge_ba || k_b)
    found=[]
    for i in range(1<<12):
        b=i.to_bytes(2,'big')+bytes(30)
        if gate('b','a',b)==target_ba:found.append(b)
    assert found==[fkeys['b']]
    kb=found[0]
    kt=X(F['pub']['b>t'],gate('b','t',kb))
    assert X(F['D'],kt)==fsecret
    result={'scope':'SYNTHETIC directed SHA edge DAG; no real source, FE, Bitcoin or quantum proof',
            'true_paths':['s-a-t','s-b-t'],'same_frozen_key':True,
            'false_directed_path_to_t':False,
            'false_undirected_xor_key_leaks':True,
            'tiny_12bit_bruteforce_guesses':4096,'tiny_bruteforce_recovers_key':True,
            'public_true_graph_reachable_by_bfs':True,
            'fundamental_gap':'a polynomial public graph of exactly qualifying paths gives a public polynomial certificate search; otherwise accepting edges must be cryptographically source-gated'}
    print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__':main()
