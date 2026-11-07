"""Run451 NON-PQ diagnostic: HMAC/SHA256 derivation and Ed25519 signatures."""
import hashlib,hmac,json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
root=hashlib.sha256(b'run451-public-fixture').digest()
ctx=('A:disprove:utxo0','B:disprove:utxo1','C:accept:utxo2')
enc=lambda x: b'claim451:'+len(x.encode()).to_bytes(4,'big')+x.encode()
key=lambda c: hmac.new(root,enc(c),hashlib.sha256).digest()
sk=[key(c) for c in ctx]
pk=[Ed25519PrivateKey.from_private_bytes(k).public_key() for k in sk]
msg=lambda c: b'claim451-sighash:'+enc(c)
def accepts(i,k):
    try:
        pk[i].verify(Ed25519PrivateKey.from_private_bytes(k).sign(msg(ctx[i])),msg(ctx[i]))
        return True
    except InvalidSignature: return False
N=0
def check(b):
    global N
    assert b
    N+=1
# Ideal source-gated release returns overpowered root on TWO valid originals.
release=lambda c,w: root if c==ctx[0] and w in ('fork-a','fork-b') else None
check(release(ctx[0],'fork-a')==release(ctx[0],'fork-b')==root)
check(release(ctx[1],'anything') is None)
for i in range(len(ctx)):
    check(accepts(i,sk[i]))
    for j in range(len(ctx)):
        if i!=j:
            check(sk[i]!=sk[j])
            check(not accepts(j,sk[i]))
for i in (1,2):
    # Root obtained from a valid A witness constructs B/C signing seeds despite false R_B/R_C.
    check(accepts(i,hmac.new(release(ctx[0],'fork-a'),enc(ctx[i]),hashlib.sha256).digest()))
check(b'abc'==b'a'+b'bc')
check(enc('ab:c')!=enc('a:bc'))
print(json.dumps({'run':451,'assertions_passed':N,'distinct_public_keys':len({p.public_bytes_raw() for p in pk}),
 'unauthorized_other_contexts_signed':2,'non_pq_diagnostic':True},sort_keys=True,separators=(',',':')))
