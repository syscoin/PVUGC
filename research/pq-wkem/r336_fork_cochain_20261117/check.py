#!/usr/bin/env python3
"""R336 finite graph cochain source-release candidate regression (NOT ORIGINAL WKEM)."""
import hashlib,json,random
R=random.Random(33620261117)
def H(b):return hashlib.sha256(b).digest()
def X(a,b):return bytes(x^y for x,y in zip(a,b))
def xr(*v):
    z=b'\0'*32
    for t in v:z=X(z,t)
    return z

def path(root, seed, branch, length):
    p=[root]
    for j in range(length):p.append(H(b'child:'+bytes([branch])+j.to_bytes(2,'big')+p[-1]+seed))
    return p

def token(v,seed):return H(b'U'+seed+v)
def edge(u,v,seed):return xr(token(u,seed),token(v,seed))
def pathpad(p,seed):return xr(*(edge(p[i],p[i+1],seed) for i in range(len(p)-1)))
def crossing(va,vb,seed,k):return xr(token(va,seed),token(vb,seed),k)

def run():
    checks=0
    observed=[]
    for t in range(128):
        seed=R.randbytes(32);k1=R.randbytes(32);k2=R.randbytes(32)
        root=H(b'anchor'+R.randbytes(32))
        length=3+t%10
        a=path(root,seed,0,length);b=path(root,seed,1,length)
        assert a[0]==b[0] and a[-1]!=b[-1]; checks+=1
        pa=pathpad(a,seed);pb=pathpad(b,seed)
        x1=crossing(a[-1],b[-1],seed,k1)
        result=xr(pa,pb,x1)
        assert result==k1;checks+=1
        assert xr(pa,pb,x1)==k1;checks+=1
        fake_a=H(b'fakeA'+seed);fake_b=H(b'fakeB'+seed)
        fake_cross=crossing(fake_a,fake_b,seed,k1)
        assert xr(fake_cross,token(fake_a,seed),token(fake_b,seed))==k1;checks+=1
        x2=crossing(a[-1],b[-1],seed,k2)
        assert xr(k1,x1,x2)==k2;checks+=1
        seed2=R.randbytes(32)
        independent_cross=crossing(a[-1],b[-1],seed2,k2)
        independent_path_tokens=xr(pathpad(a,seed2),pathpad(b,seed2))
        assert xr(independent_cross,independent_path_tokens)==k2;checks+=1
        if t<2:observed.append({'length':length,'root':root.hex()[:16], 'distinct_tips':a[-1]!=b[-1], 'early_open':result==k1, 'sibling_open':xr(k1,x1,x2)==k2})
    return {'candidate':'fork-cochain','mode':'synthetic graph hashes only, no authentic sources','assertions':checks,'fixtures':128,'samples':observed,'passed':True}
if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
