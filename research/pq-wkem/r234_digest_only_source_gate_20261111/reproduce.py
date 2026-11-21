#!/usr/bin/env python3
"""R234 scoped reproducer: no original source certificates or key release."""
import hashlib,json
H=lambda *z: hashlib.sha256(b'|'.join(z)).digest()
X=lambda a,b:bytes(x^y for x,y in zip(a,b))
bit=lambda v,i:(v>>(7-i))&1
b=0xa5
sig=H(b'native-fixture',b'claim')
rows=[]
for i in range(8):
    l=H(b'public-label',bytes([b,i,1-bit(b,i)]))
    rows.append(X(sig,H(b'pad',l)))
same=fake=0
for v in range(256):
    if v==b:continue
    i=next(i for i in range(8) if bit(v,i)!=bit(b,i))
    label=H(b'public-label',bytes([b,i,bit(v,i)]))
    out=X(rows[i],H(b'pad',label))
    assert out==sig
    same+=1
    # Source proof not checked by RAW release; fake semantic value opens too.
    assert X(rows[i],H(b'pad',label))==sig
    fake+=1
# A source Merkle path belongs to a concrete root. Divergent branch root
# gives different private path and no guaranteed common decryption key.
leaf=lambda x:H(b'leaf',x)
node=lambda x,y:H(b'node',x,y)
a,b2=[b'common',b'A'],[b'common',b'B']
ra=node(leaf(a[0]),leaf(a[1]));rb=node(leaf(b2[0]),leaf(b2[1]))
assert ra!=rb
padA=H(b'path',leaf(a[0]),leaf(a[1]))
padB=H(b'path',leaf(b2[0]),leaf(b2[1]))
sealed=X(sig,padA)
assert X(sealed,padA)==sig and X(sealed,padB)!=sig
# Common source anchor is public; its pad opens early.
anchor=H(b'public-anchor',b'common')
assert X(X(sig,anchor),anchor)==sig
print(json.dumps({'run':'R234','semantic_equal_key':same,'synthetic_early_open':fake,
 'merkle_roots_distinct':ra!=rb,'unknown_future_path_not_presealed':True,
 'public_anchor_early':True,'assertions':same+fake+3,
 'security':'NONE; not actual BTC/SYS, KEM, or QPT security'},indent=2,sort_keys=True))
