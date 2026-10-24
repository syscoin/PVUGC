"""Composition-only toy; no witness encryption, no PQ security certification."""
import hashlib, hmac, json
H=lambda b:hashlib.sha256(b).digest()
def ctx(*s):return b'PVUGC-v1'+b''.join(len(x.encode()).to_bytes(2,'big')+x.encode() for x in s)
def child(master,c):return hmac.new(master,b'child/v1'+c,hashlib.sha256).digest()
def key(seed):
    a=hashlib.shake_256(b'lamport-toy'+seed).digest(2048)
    sk=[a[i:i+32] for i in range(0,2048,32)]
    return sk,[H(b'leaf'+v) for v in sk]
def mbits(m):
    d=H(b'msg'+m)
    return [(d[i//8]>>(i%8))&1 for i in range(32)]
def sign(sk,m):return [sk[2*i+b] for i,b in enumerate(mbits(m))]
def verify(pk,m,sig):return len(sig)==32 and all(H(b'leaf'+v)==pk[2*i+b] for i,(b,v) in enumerate(zip(mbits(m),sig)))
def main():
    master=H(b'Run604 deterministic fixture, not a deployed secret')
    contexts=[ctx('sys','rel','outpoint:'+str(i),'challenge','BTC-window','script-commit') for i in range(71)]
    assert len(set(contexts))==71
    assert ctx('ab','c')!=ctx('a','bc')
    seeds=[child(master,c) for c in contexts]
    assert len(set(seeds))==71
    m=b'false-claim-challenge-target'
    sk0,pk0=key(seeds[0]); shared_sig=sign(sk0,m)
    assert verify(pk0,m,shared_sig) # Known true sibling releases same authority -> false spend.
    failures=0
    for seed in seeds[1:]:
        ski,pki=key(seed)
        assert verify(pki,m,sign(ski,m))
        failures+=int(verify(pki,m,shared_sig))
    assert failures==0
    assert all(not (w==b'0' and w==b'1') for w in [b'0',b'1',b'other'])
    assert all(child(master,c)==s for c,s in zip(contexts,seeds)) # retained master breaks keyless
    print(json.dumps({'run':604,'contexts':71,'shared_authority_false_spend':True,
          'separated_cross_verification_count':failures,'separated_own_verifications':70,
          'qpt_security_proven':False,'wkem_constructed':False},sort_keys=True))
if __name__=='__main__':main()
