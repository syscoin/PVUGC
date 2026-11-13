"""R241 SHA gate-garbling regression; NOT secure WE or BTC/SYS verification."""
import hashlib, json

def h(*fields):
    p=b'R241'
    for f in fields:
        if isinstance(f,str): f=f.encode()
        p+=len(f).to_bytes(4,'big')+f
    return hashlib.sha256(p).digest()[:16]
def x(a,b):return bytes(i^j for i,j in zip(a,b))
def labs(root):return {z:[h('label',root,z,bytes([b])) for b in (0,1)] for z in ('x','nx','out')}
def make(g,ins,out,fn,L):
    rows=[]
    from itertools import product
    for bits in product((0,1),repeat=len(ins)):
        ls=[L[w][b] for w,b in zip(ins,bits)]
        v=L[out][fn(*bits)]
        rows.append((x(v,h('pad',g,*ls)),h('auth',g,*ls,v)))
    return (g,ins,out,rows)
def apply(g,ls):
    name,ins,out,rows=g
    matches=[v for a,t in rows if (v:=x(a,h('pad',name,*ls))) and h('auth',name,*ls,v)==t]
    assert len(matches)<=1
    return matches[0] if matches else None

def closure(G,L):
    vals={'x':set(L['x'])}
    for g in G:
        from itertools import product
        vals[g[2]]={v for args in product(*(vals[i] for i in g[1])) if (v:=apply(g,args))}
    return vals

def gates(L):
    return [make('not',('x',),'nx',lambda b:1-b,L),
            make('and',('x','nx'),'out',lambda a,b:a&b,L)]
root0=h('source','root0');root1=h('source','root1')
L=labs(root0);G=gates(L);secret=h('frozen-cancel');c=x(secret,h('seal',L['out'][1]))
assert all(apply(G[1],[L['x'][b],apply(G[0],[L['x'][b]])])==L['out'][0] for b in (0,1))
assert L['out'][1] in closure(G,L)['out']
assert x(c,h('seal',L['out'][1]))==secret
assert apply(G[0],[labs(root1)['x'][0]]) is None
assert L['out'][1] in closure(G,L)['out'] # fixed-root binding does not repair mixing
print(json.dumps({'run':'R241_MIN','checks':5,'false_world_broken':True,
 'source_root_repair_all_witness_correct':False,'btc_sys_source_verifier':False,
 'qpt_security':False},sort_keys=True,indent=2))
