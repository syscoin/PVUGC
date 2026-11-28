"""R212 finite SHA256 residual-factorization check; NOT original source or KEM."""
import hashlib, json

def h(tag, *items):
    d = tag.encode() + b'\0'
    for x in items: d += len(x).to_bytes(4, 'big') + x
    return hashlib.sha256(d).digest()

def xor(a,b): return bytes(x^y for x,y in zip(a,b))
def r(z):
    a,b,c=z
    return bytes(((a+b-2*a*b-1)%257, (c-a*b)%257))

valid=((0,1,0),(1,0,0)); results={'all_valid_same':0,'early_open':0,'trace_other_fails':0,'normalized_early_open':0}
for i in range(64):
    x=i.to_bytes(4,'big'); sig=h('sigma',x); context=h('context',x)
    def g(res): return h('nonlinear-hash-pad',context,res)
    ciphertext=xor(sig,g(b'\0\0'))
    for z in valid:
        assert r(z)==b'\0\0' and xor(ciphertext,g(r(z)))==sig
        results['all_valid_same']+=1
    assert xor(ciphertext,g(b'\0\0'))==sig
    results['early_open']+=1
    def trace(z): return h('transcript',context,bytes(z))
    def g2(z): return h('trace-pad',context,r(z),trace(z))
    c2=xor(sig,g2(valid[0]))
    assert xor(c2,g2(valid[1]))!=sig
    results['trace_other_fails']+=1
    normalized=h('public-anchor',context)
    c3=xor(sig,h('normalized-pad',context,b'\0\0',normalized))
    assert xor(c3,h('normalized-pad',context,b'\0\0',normalized))==sig
    results['normalized_early_open']+=1
print(json.dumps({'run':'R212-mini','counts':results,'security':'no; deterministic early recovery'},sort_keys=True,indent=2))
