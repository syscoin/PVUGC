#!/usr/bin/env python3
"""R207 compact exact regression: public SHA-gate masks are not WKEM."""
import hashlib, json
p=257
H=lambda x:hashlib.sha256(x).digest()
checks=0
for seed in range(128):
    s=seed.to_bytes(4,'big')
    r=[int.from_bytes(H(b'R207/mask'+s+bytes([i])),'big')%p for i in range(5)]
    K=int.from_bytes(H(b'R207/key'+s),'big')%p
    # Public coefficients of P=K+r0*(a+b-2ab-1)+r1*(c-ab)
    #                      +r2*(a*a-a)+r3*(b*b-b)+r4*(c*c-c).
    C0=(K-r[0])%p
    Ca=(r[0]-r[2])%p
    Cb=(r[0]-r[3])%p
    Cab=(-2*r[0]-r[1])%p
    Cc=(r[1]-r[4])%p
    Ca2,Cb2,Cc2=r[2:]
    def evaluate(a,b,c):
        return (C0+Ca*a+Cb*b+Cab*a*b+Cc*c+Ca2*a*a+Cb2*b*b+Cc2*c*c)%p
    # Two different valid circuit assignments recover the SAME prechosen K.
    for z in [(0,1,0),(1,0,0)]:
        assert evaluate(*z)==K
        checks+=1
    # The PUBLIC coefficient quotient, with no original witness, recovers K.
    stolen=(C0+Ca+Ca2)%p
    assert stolen==K
    checks+=1
    # A SHA-masked 32-byte synthetic cancellation capability then opens early.
    sigma=H(b'R207/synthetic-native-capability'+s)
    pad=H(b'R207/pad'+K.to_bytes(2,'big'))
    D=bytes(x^y for x,y in zip(sigma,pad))
    pad_from_public=H(b'R207/pad'+stolen.to_bytes(2,'big'))
    assert bytes(x^y for x,y in zip(D,pad_from_public))==sigma
    checks+=1
print(json.dumps({'run':'R207','source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),
                  'seeds':128,'assertions':checks,
                  'result':'two valid witnesses share K, but public coefficient attack opens sigma without any witness',
                  'scope':'synthetic Boolean/AND constraints, not deployed SHA/AuxPoW or native PQ'},sort_keys=True,indent=2))
