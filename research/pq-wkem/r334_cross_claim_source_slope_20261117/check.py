#!/usr/bin/env python3
"""R334: exact cross-capsule affine-slope regression. Not ORIGINAL source WE."""
import hashlib, json, random
P = 2**255 - 19
rng = random.Random(0x334C0A5E)
def field(): return rng.randrange(1,P)
def rnd(n): return rng.randbytes(n)
def pad(cid, b, n=512):
    prefix = b'PVUGC-R334-cancel-v1\x00'
    return hashlib.shake_256(prefix + cid + b.to_bytes(32,'little')).digest(n)
def x(a,b): return bytes(u^v for u,v in zip(a,b))
def receipt(a,b,m): return (a+b*m)%P
def recover(y0,y1,m0,m1): return ((y1-y0)*pow((m1-m0)%P,-1,P))%P
m0,m1=7,19
cid_a=b'original-claim-A'; cid_b=b'original-claim-B'
s_a,s_b=rnd(512),rnd(512)
a,b=field(),field()
y0,y1=receipt(a,b,m0),receipt(a,b,m1)
c_a=x(s_a,pad(cid_a,b)); c_b=x(s_b,pad(cid_b,b))
assert recover(y0,y1,m0,m1)==b
assert x(c_a,pad(cid_a,recover(y0,y1,m0,m1)))==s_a
assert x(c_b,pad(cid_b,recover(y0,y1,m0,m1)))==s_b
assert pad(cid_a,b)!=pad(cid_b,b)  # domain separation still insufficient
# Independent per-claim hypothetical source issuers prevent this *specific* cross-open,
# but do NOT give a public source-native Build/Open.
a_a,b_a=field(),field();a_b,b_b=field(),field()
y_a0,y_a1=receipt(a_a,b_a,m0),receipt(a_a,b_a,m1)
y_b0=receipt(a_b,b_b,m0)
c_ai=x(s_a,pad(cid_a,b_a));c_bi=x(s_b,pad(cid_b,b_b))
assert recover(y_a0,y_a1,m0,m1)==b_a
assert x(c_ai,pad(cid_a,b_a))==s_a
assert x(c_bi,pad(cid_b,b_a))!=s_b
assert x(c_bi,pad(cid_b,b_b))==s_b
# For each possible b_B, there is exactly one compatible a_B given the ONE public receipt,
# so b_B remains perfectly uniform under independent setup.
for probe_b in range(103):
    probe_a=(y_b0-m0*probe_b)%P
    assert receipt(probe_a,probe_b,m0)==y_b0
print(json.dumps({'name':'R334 hypothetical issuer/cross-capsule regression','global_slope_recovered':True,'global_slope_opens_distinct_domain_separated_sibling':True,'independent_slope_prevents_same_extraction':True,'public_original_source_receipt_implemented':False,'test_source':'synthetic seeded field receipts only','setup_model':'honest independent uniform scalars, no malicious/source simulation'},sort_keys=True))
