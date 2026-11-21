#!/usr/bin/env python3
"""Explicit-DAG hash-token release trial. Synthetic graph; NOT Bitcoin/Syscoin WE.

SOURCE FILE is limited to an independent, explicit graph; labels are random and
an ideal RO is locally emulated for a test-only transcript coupling. SHA256
version verifies correctness; ideal-RO coupling is not a concrete SHA attack.
"""
import hashlib, json, random, collections

N=32

def bx(a,b): return bytes(x ^ y for x,y in zip(a,b))
def digest(data): return hashlib.sha256(data).digest()
def nodes_edges(edges): return sorted(set([x for e in edges for x in e]))
def paths(edges,start,end):
    adj=collections.defaultdict(list)
    for u,v in edges: adj[u].append(v)
    q=collections.deque([(start,)])
    while q:
        p=q.popleft()
        if p[-1]==end:
            yield p
        else:
            for v in adj[p[-1]]:
                if v not in p: q.append(p+(v,))

class EmulatedRO:
    def __init__(self): self.values={}
    def value(self,domain,edge_id,key):
        t=domain + b'/' + edge_id.encode() + b'/' + key
        return self.values[t]

def ro_point(domain,e,k): return domain+b'/'+e.encode()+b'/'+k

def build_explicit(edges,src,dst,seed,secret,hash_mode=True,domain=b'claim-one'):
    r=random.Random(seed)
    verts=nodes_edges(edges)
    assert src in verts and dst in verts
    kk={v:r.randbytes(N) for v in verts}
    kk[dst]=secret
    C={}
    if hash_mode:
        for u,v in edges:
            e=f'{u}>{v}'
            C[e]=bx(kk[v],digest(ro_point(domain,e,kk[u])))
        return C,kk,None
    ro=EmulatedRO()
    for u,v in edges:
        e=f'{u}>{v}'
        p=ro_point(domain,e,kk[u])
        assert p not in ro.values
        ro.values[p]=r.randbytes(N)
        C[e]=bx(kk[v],ro.values[p])
    return C,kk,ro

def open_path(edges,src,dst,C,k_start,p,domain=b'claim-one',ro=None):
    if not p or p[0]!=src or p[-1]!=dst:
        return None
    known=set(edges)
    label=k_start
    for u,v in zip(p,p[1:]):
        if (u,v) not in known: return None
        e=f'{u}>{v}'
        h=digest(ro_point(domain,e,label)) if ro is None else ro.value(domain,e,label)
        label=bx(C[e],h)
    return label

def main():
    sec=digest(b'PUBLIC EXPERIMENT: frozen message, not a key')
    sec2=digest(b'OTHER-PAYLOAD')
    edges_true=[('s','a'),('a','c'),('c','t'),('s','b'),('b','d'),('d','t'),('a','z'),('b','z')]
    paths_true=list(paths(edges_true,'s','t'))
    assert len(paths_true)==2
    C,keys,_=build_explicit(edges_true,'s','t',101,sec)
    outcomes=[open_path(edges_true,'s','t',C,keys['s'],p) for p in paths_true]
    assert outcomes==[sec,sec]
    # The complete edge list permits BFS to find an accepted path without source work.
    bfs_path=paths_true[0]
    assert open_path(edges_true,'s','t',C,keys['s'],bfs_path)==sec
    # FALSE: t has edges from disconnected vertices, but no s-to-t path.
    edges_false=[('s','a'),('a','b'),('b','c'),('u','t'),('v','t'),('u','v'),('v','x')]
    assert not list(paths(edges_false,'s','t'))
    C0,k0,ro0=build_explicit(edges_false,'s','t',212,sec,False)
    # Explicit ROM coupling under S -> S': reprogram ONLY incoming-t hidden points.
    C1,k1,ro1=build_explicit(edges_false,'s','t',212,sec2,False)
    # The constructions use identical hidden keys for all vertices except t.
    for v in nodes_edges(edges_false):
        if v!='t': assert k0[v]==k1[v]
    delta=bx(sec,sec2)
    ro1.values=dict(ro0.values)
    for u,v in edges_false:
        if v=='t':
            e=f'{u}>{v}'
            p=ro_point(b'claim-one',e,k0[u])
            ro1.values[p]=bx(ro0.values[p],delta)
    C1={}
    for u,v in edges_false:
        e=f'{u}>{v}'
        C1[e]=bx(k1[v],ro1.value(b'claim-one',e,k1[u]))
    assert C0==C1
    reachable=set(['s']); changed=True
    while changed:
        before=len(reachable)
        reachable|={v for u,v in edges_false if u in reachable}
        changed=(len(reachable)!=before)
    assert 't' not in reachable
    switched={ro_point(b'claim-one',f'{u}>{v}',k0[u]) for u,v in edges_false if v=='t'}
    reachable_queries={ro_point(b'claim-one',f'{u}>{v}',k0[u]) for u,v in edges_false if u in reachable}
    assert not (switched & reachable_queries)
    result={
       'scope':'EXPLICIT polynomial-size DAG only; not ORIGINAL certificate; no QPT proof',
       'true_path_count':len(paths_true),'true_frozen_same':all(x==sec for x in outcomes),
       'true_path_publicly_found_by_bfs':list(bfs_path),
       'false_no_public_source_to_target_path':True,
       'false_rom_coupled_capsules_identical':C0==C1,
       'false_rom_changed_points_count':len(switched),
       'reachable_oracle_points_intersect_changed':bool(switched & reachable_queries),
       'domain_key_separation_required_for_siblings':True,
       'no_source_certificate_or_native_signature_or_fe':True,
    }
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':main()
