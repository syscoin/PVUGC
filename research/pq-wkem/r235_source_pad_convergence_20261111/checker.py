#!/usr/bin/env python3
"""R235: source-certificate hash-pad convergence and telescoping repairs.

TOY SHA256d parent wrappers, not Bitcoin consensus / AuxPoW implementation.
No cryptographic security tests; no QPT, no genuine Build/Open.
"""
import hashlib, json

N=0

def ck(ok,name):
    global N
    assert ok, name
    N += 1

def sha(x): return hashlib.sha256(x).digest()
def h2(x): return sha(sha(x))
def H(tag, *parts):
    z=b'SCP235/'+tag.encode()+b'\0'
    return sha(z+b''.join(len(p).to_bytes(4,'big')+p for p in parts))
def xor(a,b): return bytes(x^y for x,y in zip(a,b))
def xorkey(seq):
    out=b'\0'*32
    for x in seq: out=xor(out,x)
    return out

# Parent header and coinbase commitment stand-ins: source links are synthetic.
# Target means ~10-bit work; this is NOT a real AuxPoW, Bitcoin DAA or anchor.
TARGET=(1<<256)//(1<<10)
def mine(child,prev,from_nonce=0):
    cb=b'COINBASE-STANDIN/'+child
    merkle=sha(cb)
    for n in range(from_nonce,10**6):
        head=b'PARENT-STANDIN/'+prev+merkle+n.to_bytes(4,'little')
        digest=h2(head)
        if int.from_bytes(digest,'little')<TARGET:
            return {'child':child,'cb':cb,'root':merkle,'prev':prev,'nonce':n,'header':head,'work':digest}
    raise RuntimeError('toy PoW target unexpectedly unreachable')
def valid(c):
    return (c['cb']==b'COINBASE-STANDIN/'+c['child']
            and c['root']==sha(c['cb'])
            and c['header']==b'PARENT-STANDIN/'+c['prev']+c['root']+c['nonce'].to_bytes(4,'little')
            and c['work']==h2(c['header'])
            and int.from_bytes(c['work'],'little')<TARGET)

def cert_bytes(c):
    return c['header']+c['work']+c['cb']
def pad(c): return H('pad',cert_bytes(c))

# Distinct valid-work certificates for the same Syscoin child outcome.
child=H('child',b'baseline')
prev=H('prev',b'public BTC anchor')
a=mine(child,prev)
b=mine(child,prev,a['nonce']+1)
ck(valid(a) and valid(b),'two valid toy parent-work certificates')
ck(a['nonce']!=b['nonce'] and a['work']!=b['work'],'distinct parent certificates')
ck(a['child']==b['child'],'same source semantic child')
ck(pad(a)!=pad(b),'different transcript hashes')
sigma=H('frozen signature',b'claim123')
E=xor(sigma,pad(a))
ck(xor(E,pad(a))==sigma,'pad opens for selected cert')
ck(xor(E,pad(b))!=sigma,'pad fails for alternative cert')
# Exact necessary and sufficient equation for an XOR-pad gate.
ck((xor(E,pad(a))==xor(E,pad(b))) == (pad(a)==pad(b)),
   'common frozen output requires equal pads')

# A source fork can have equal-height competing child identities with a shared parent.
child_alt=H('child',b'conflicting header')
c=mine(child_alt,prev)
ck(valid(c) and c['child']!=a['child'],'toy semantic disagreement')
ck(pad(c)!=pad(a),'fork also changes transcript pad')
ck(xor(E,pad(c))!=sigma,'fork witness not one fixed-pad opening')

# SHA hash-link sequence of authenticated transitions, with a common prior tip.
# telescoping accumulator: XOR_i [H(node_i) XOR H(node_{i+1})]
common=H('history',b'common')
A=[common]
B=[common]
for i in range(5):
    A.append(H('linked header',A[-1],b'branch-A',bytes([i])))
    B.append(H('linked header',B[-1],b'branch-B',bytes([i])))

def telescope(path):
    return xorkey([xor(H('vertex',path[i]),H('vertex',path[i+1]))
                   for i in range(len(path)-1)])

def boundary(path):return xor(H('vertex',path[0]),H('vertex',path[-1]))

for path in (A,B,A[:2],A[:4],B[:3],B[:5]):
    ck(telescope(path)==boundary(path),'telescoping identity')
ck(telescope(A)!=telescope(B),'distinct endpoints => distinct masks')
ck(H('vertex',common)==H('vertex',A[0]),'shared starting endpoint public')
# A synthetic diamond with arbitrary intermediate nodes and SAME endpoints:
end=H('fixed',b'same endpoint')
p1=[common,H('intermediate',b'P'),end]
p2=[common,H('intermediate',b'Q'),end]
ck(p1!=p2 and telescope(p1)==telescope(p2),'different paths same endpoints')
ck(telescope(p1)==xor(H('vertex',common),H('vertex',end)),
   'public endpoint bypass of purported witness-dependent accumulator')
# Common-prefix repair leaks because prefix before divergence already public.
fixed_prefix=H('vertex',common)
E_common=xor(sigma,fixed_prefix)
ck(xor(E_common,H('vertex',A[0]))==sigma,'valid prefix opens')
ck(xor(E_common,fixed_prefix)==sigma,'public prefix opens without witness')

# Product/non-XOR version, group operation modulo a prime:
# For publicly readable edge potential phi, path-invariant sum is phi(end)-phi(start)
p=(1<<127)-1
def phi(z):return int.from_bytes(H('potential',z),'big')%p
def edge(u,v):return (phi(v)-phi(u))%p
for path in (A,B,p1,p2):
    v=sum(edge(path[i],path[i+1]) for i in range(len(path)-1))%p
    ck(v==(phi(path[-1])-phi(path[0]))%p,'additive path invariant boundary')
ck(sum(edge(p1[i],p1[i+1]) for i in range(2))%p
   ==sum(edge(p2[i],p2[i+1]) for i in range(2))%p,
   'diamond paths same publicly computable invariant')

print(json.dumps({'run':'R235-SCP','toy_target_bits':10,'assertions':N,
  'same_child_distinct_parent_work':[a['work'].hex(),b['work'].hex()],
  'distinct_semantic_child_work':c['work'].hex(),
  'sha256_source':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
  'status':'source-conditioned common key NOT instantiated; local functionality only'},
  sort_keys=True,indent=2))
