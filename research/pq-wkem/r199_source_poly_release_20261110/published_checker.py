#!/usr/bin/env python3
"""R199 reproducible algebra-only regression. NO actual BTC/SYS or WKEM."""
import hashlib, json
p=65537

def h(tag,s):
    return int.from_bytes(hashlib.sha256(tag.encode()+b'\0'+s).digest(),'big')%p

def recover(z0,y0,z1,y1):
    assert z0!=z1
    return ((z1*y0-z0*y1)*pow(z1-z0,-1,p))%p

def run():
    good=leak=bad=0
    for t in range(128):
        seed=t.to_bytes(4,'big')
        k=h('key',seed);a=h('slope',seed)
        z=[1+(h('outcome',seed+bytes([i]))%(p-1)) for i in range(3)]
        if len(set(z))!=3:continue
        y=[(k+a*x)%p for x in z]
        assert recover(z[0],y[0],z[1],y[1])==k
        assert recover(z[1],y[1],z[2],y[2])==k
        assert recover(z[0],y[0],z[2],y[2])==k
        good+=1
        assert (k+a*0)%p==k
        assert recover(3,(k+3*a)%p,5,(k+5*a)%p)==k
        leak+=1
        q=[h('public-hash',seed+bytes([i])) for i in range(3)]
        if recover(z[0],q[0],z[1],q[1])!=recover(z[0],q[0],z[2],q[2]):bad+=1
    for k in (0,19,256):
        for z in (1,7,256):
            assert len({(k+a*z)%257 for a in range(257)})==257
    return {'run':'R199-SOURCE-POLY-20261110','qualifying_synthetic_triplets':good,
            'early_public_coefficient_recoveries':leak,
            'public_hash_non_collinearity':bad,
            'isolated_one_share_bijections':9,
            'scope':'finite-field synthetic arithmetic only; NO ORIGINAL Build/Open, mining or QPT proof'}

if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
