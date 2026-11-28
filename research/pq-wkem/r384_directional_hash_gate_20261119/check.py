#!/usr/bin/env python3
"""R384 bounded SOURCE-INCOMPLETE graph-gate regression; NOT FE or actual bridge.
One-way hash-wrapped directed edges are publicly serialized; source-shaped
PoW table is deliberately enumerated at Build (not practical)."""
import hashlib, json, math

P=101

def mul(a,b):
    return ((a[0]*b[0]+a[1]*b[2])%P,(a[0]*b[1]+a[1]*b[3])%P,(a[2]*b[0]+a[3]*b[2])%P,(a[2]*b[1]+a[3]*b[3])%P)
def inv(a):
    det=(a[0]*a[3]-a[1]*a[2])%P
    q=pow(det,-1,P)
    return ((a[3]*q)%P,(-a[1]*q)%P,(-a[2]*q)%P,(a[0]*q)%P)
def det(a): return (a[0]*a[3]-a[1]*a[2])%P

def sha(*b): return hashlib.sha256(b''.join(b)).digest()
def xor(a,b): return bytes(x^y for x,y in zip(a,b))
def key(node): return sha(b'PRIVATE FIXTURE seed R384',node.encode())
def edgepad(u,v,ku): return sha(b'R384 EDGE',u.encode()+b'\x00'+v.encode()+b'\x00',ku)
def outpad(kt): return sha(b'R384 OUT',kt)

def encode_graph(edges,nodes,root,target,secret):
    # deterministic private keys only to reproduce; all actual crypto schemes need fresh randomness
    ks={v:key(v) for v in nodes}
    cs={(u,v):xor(ks[v],edgepad(u,v,ks[u])) for u,v in edges}
    D=xor(secret,outpad(ks[target]))
    return {'root':root,'target':target,'edges':cs,'root_key':ks[root],'D':D,'keys':ks}

def follow(enc,path):
    u=path[0]; ku=enc['root_key'];assert u==enc['root']
    for v in path[1:]:
        assert (u,v) in enc['edges']
        ku=xor(enc['edges'][u,v],edgepad(u,v,ku))
        u=v
    if u!=enc['target']: return None
    return xor(enc['D'],outpad(ku))

# A concrete noncommutative algebra bypass of a no-directed-path gate.
I=(1,0,0,1)
g={'r':I, 'a':(2,3,1,4),'c':(6,2,7,8),'t':(5,1,4,7)}
assert all(det(x) for x in g.values())
M={(u,v):mul(inv(g[u]),g[v]) for u,v in [('r','a'),('c','a'),('c','t')]}
undirected=mul(mul(M['r','a'],inv(M['c','a'])),M['c','t'])
assert undirected==g['t']

S=sha(b'FROZEN SYNTHETIC SIGNATURE PAYLOAD')
false_g=encode_graph([('r','a'),('c','a'),('c','t')],set(g),'r','t',S)
assert ('a','c') not in false_g['edges']
assert follow(false_g,['r','a']) is None
true_g=encode_graph([('r','a'),('a','c'),('c','t')],set(g),'r','t',S)
assert follow(true_g,['r','a','c','t'])==S

# Explicit SHA256d workload -> exponential prefix tree (intentionally impractical).
n=10; d=7; total_nodes=(2**(n+1)-1)+1
prefix_nodes=sum(2**i for i in range(n+1))
headers=[]
for i in range(2**n):
    b=i.to_bytes(2,'little')
    digest=sha(sha(b'CERT-PLACEHOLDER:' + b))
    if int.from_bytes(digest,'big') < 2**(256-d):
        headers.append(i)
assert 0<len(headers)<2**n
# Merely enumerating all accepted headers makes the accepted witnesses public.
# Full prefix-node expansion requires 2^(n+1)-1 nodes and a terminal.
res={
 'scope':'synthetic explicit directed hash graph and SOURCE-INCOMPLETE SHA certificate prefix table',
 'noncommuting_gauges':mul(g['a'],g['c'])!=mul(g['c'],g['a']),
 'no_forward_path_but_undirected_group_extraction':undirected==g['t'],
 'forward_hash_gate_opens_on_path':follow(true_g,['r','a','c','t'])==S,
 'false_graph_has_no_directed_path':True,
 'sha_input_bits':n,
 'sha_prefix_target_bits':d,
 'sha_candidates_enumerated_at_build':2**n,
 'accepted_cert_indices':headers,
 'prefix_nodes_plus_terminal':total_nodes,
 'edge_ciphertexts_needed_at_least':(prefix_nodes-1)+len(headers),
 'source_qualification':'NONE: no real AuxPoW, BTC best chain, Syscoin light client, burn, fork, or contextual activation',
 'qpt_security':'NOT PROVED; random-oracle hidden-key hybrid is a proposal only',
 'practical_original_build_open':False,
}
print(json.dumps(res,sort_keys=True,indent=2))
