#!/usr/bin/env python3
"""R190 exact pinned std::search control-flow emulation + synthetic ancestry.
Not full Syscoin/Bitcoin, native release, or a QPT experiment.
"""
import hashlib, json, struct
M=b'\xfa\xbe\x6d\x6d'   # fixture marker, NOT pchSyscoinHeader
checks=0
def ck(x):
    global checks
    assert x
    checks+=1
def tag(b,h): return b+struct.pack('<I',h)
def scan(outputs,expected):
    found=False
    for out in outputs:
        if not out.startswith(b'\x6a'): continue
        p=out.find(M)
        if p<0:continue
        if out.find(expected,p+len(M))<0:return 'bad'
        if found:return 'multiple'
        found=True
    return 'accept' if found else 'missing'
def H(data):return hashlib.sha256(hashlib.sha256(data).digest()).digest()
def build(n,seed,common=None,div=0):
    if common is not None:out=common[:div]
    else:out=[]
    while len(out)<=n:
        h=len(out)
        out.append(H(b'child'+struct.pack('<I',h)+(out[-1] if out else bytes(32))+seed))
    return out
def sem(chain,n):
    h=10*((n-6)//10)
    return h,chain[h]
def conflict(a,b):
    ha,A=sem(*a);hb,B=sem(*b)
    return (A!=B) if ha==hb else ((b[0][ha]!=A) if ha<hb else (a[0][hb]!=B))
def main():
    A=build(40,b'A')
    B=build(40,b'B',common=A,div=19)
    L=build(40,b'L',common=A,div=35)
    for n in range(26,40):
        h,v=sem(A,n); expected=tag(v,h)
        wrong=tag(H(b'wrong'+bytes([n])),h)
        same_output=b'\x6a'+M+wrong+M+expected
        ck(scan([same_output],expected)=='accept')
        ck(same_output[same_output.find(M)+len(M):][:36]==wrong)
        ck(scan([b'\x6a'+M+wrong],expected)=='bad')
        ck(scan([b'\x6a'+M+expected,b'\x6a'+M+expected],expected)=='multiple')
        ck(not conflict((A,n),(A,n))) # work certificate variants do not change child
        ck(conflict((A,n),(B,n)))    # actual different child ancestry
        ck(not conflict((A,n),(L,n)))# later fork not exposed by reference yet
    for n in range(160):
        wanted=tag(bytes([n])*32,2000000+n)
        bad=tag(bytes([(n+1)%256])*32,2000000+n)
        ck(scan([b'\x6a'+M+bad+M+wanted],wanted)=='accept')
        ck(scan([b'\x6a'+M+bad],wanted)=='bad')
    return dict(run='R190 pinned-parser and semantic identity',assertions=checks,
        release_gate=False,real_source_validation=False)
if __name__=='__main__':print(json.dumps(main(),sort_keys=True))
