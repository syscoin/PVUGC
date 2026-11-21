#!/usr/bin/env python3
"""R324: explicit source-output-factorized release failure, deterministic SHA256d fixtures.
Not Bitcoin consensus, native signatures, quantum attacks, or an ORIGINAL Build/Open.
"""
import hashlib, json, struct

def sha(b): return hashlib.sha256(b).digest()
def hd(b): return sha(sha(b))
def header(prev, nonce, merkle):
    assert len(prev)==len(merkle)==32
    return struct.pack('<I',0x20100180) + prev + merkle + struct.pack('<III',1730000000,0x207fffff,nonce)
def xor(a,b): return bytes(x^y for x,y in zip(a,b))
def target(h, bits=4): return int.from_bytes(h,'big')>>(256-bits)==0

def find(prefix, merkle):
    for nonce in range(4096):
        h=header(prefix,nonce,merkle)
        if target(hd(h)): return h,nonce,hd(h)
    raise AssertionError('no toy target hit')

A=sha(b'R324:fixed-bitcoin-parent-anchored-header')
B=sha(b'R324:unrelated-parent-not-in-anchor-chain')
M=sha(b'R324:toy-merkle-root')
real,nr,yr=find(A,M)
fake,nf,yf=find(B,M)
assert real[4:36]==A and fake[4:36]==B and A!=B
assert target(yr) and target(yf)
assert len(real)==len(fake)==80
# Prefix-branch PRF constrained key: any bearer of a publicly disclosed
# prefix seed can compute the pad on that subtree, regardless of preimage.
seed=sha(b'R324:honestly-erased-prefix-GGM-seed')
sigma=sha(b'R324:synthetic-frozen-signature')
mask=sha(b'R324:mask:'+seed)
D=xor(sigma,mask)
public_capsule={'prefix':'0000','prefix_key':seed.hex(),'D':D.hex()}
# Extraction from public C without a header/preimage.
extracted=xor(bytes.fromhex(public_capsule['D']),
              sha(b'R324:mask:'+bytes.fromhex(public_capsule['prefix_key'])))
assert extracted==sigma

def open_without_source(digest):
    assert target(digest)
    return extracted

assert open_without_source(yr)==sigma
assert open_without_source(yf)==sigma
zero=b'\x00'*32
assert target(zero)
assert open_without_source(zero)==sigma
# In the fixture, the 'original relevance' predicate is a stipulated fixed
# parent certificate membership, so fake and zero are not admitted.
def synthetic_relevance(h):
    return isinstance(h, bytes) and len(h)==80 and h[4:36]==A and target(hd(h))
assert synthetic_relevance(real)
assert not synthetic_relevance(fake)
# Uniform 256-bit zero does not supply any header bytes, much less the chain.
# For prefix target 2^-t, the public syntactic set size is 2^(256-t)
assert 256-4==252
# Enforce every-witness same capability on independent accepted anchored samples.
openings=[]
for nonce in range(256):
    h=header(A,nonce,M)
    if synthetic_relevance(h):
        assert open_without_source(hd(h))==sigma
        openings.append(nonce)
assert len(openings)>2
# Repair attempt: use a genuine SHA-based GGM tree rather than one constant
# prefix pad. This avoids a trivially repeated per-prefix mask but needs
# an accepted leaf ciphertext for every accepted projected digest.
def ggm(s, bits):
    for bit in bits:
        assert bit in (0,1)
        s=sha(b'R324:GGM:' + bytes([bit]) + s)
    return s
def bits8(n): return [(n>>(7-i))&1 for i in range(8)]
root=sha(b'R324:GGM:honest:root')
prefix_seed=ggm(root, [0]*4)
leaf_rows=[]
for suffix in range(256):
    leaf=ggm(prefix_seed,bits8(suffix))
    leaf_rows.append(xor(sigma,sha(b'R324:leafmask:'+leaf)))
assert len(leaf_rows)==256

def open_leaf_from_projected_digest(digest):
    assert len(digest)==32 and target(digest)
    # Extract the next eight source-hash bits after the four-zero prefix.
    suffix=int.from_bytes(digest[:2],'big') & 0x0fff
    suffix >>= 4
    return xor(leaf_rows[suffix],sha(b'R324:leafmask:'+ggm(prefix_seed,bits8(suffix))))

assert open_leaf_from_projected_digest(yr)==sigma
assert open_leaf_from_projected_digest(yf)==sigma
assert open_leaf_from_projected_digest(zero)==sigma
# A partial preselected digest whitelist improves scarcity but loses
# every-witness completeness: some honestly qualifying headers' SHA outputs
# fall outside it. Here the permitted whitelist consists of 128 out of 256
# target suffixes, selected before inspecting any eligible source header.
preselected=set(range(128))
covered=[]
uncovered=[]
for nonce in openings:
    digest=hd(header(A,nonce,M))
    suffix=(int.from_bytes(digest[:2],'big')&0x0fff)>>4
    (covered if suffix in preselected else uncovered).append(nonce)
assert covered and uncovered
for nonce in openings:
    assert open_leaf_from_projected_digest(hd(header(A,nonce,M)))==sigma
report={
  'candidate':'R324-public-SHA-output-prefix-key',
  'sha256d_real':yr.hex(), 'sha256d_unrelated':yf.hex(),
  'anchored_nonce':nr,'unrelated_nonce':nf,
  'anchored_accepted_in_256':len(openings),
  'every_synthetic_anchored_opens':True,
  'unrelated_nonmember_opens':True,
  'zero_digest_without_preimage_opens':True,
  'synthetic_capability_sha256':sha(sigma).hex(),
  'public_C_sha256':sha(json.dumps(public_capsule,sort_keys=True).encode()).hex(),
  'toy_prefix_accepted_digest_count':'2^252',
  'ggm_leaf_rows':len(leaf_rows),
  'ggm_leaf_row_bytes':sum(map(len,leaf_rows)),
  'partial_whitelist_covered_anchored':len(covered),
  'partial_whitelist_uncovered_anchored':len(uncovered),
  'ggm_public_zero_digest_extracts':open_leaf_from_projected_digest(zero)==sigma,
  'note':'Class-conditional direct classical public extraction, not network/ORIGINAL/QPT simulation.'
}
print(json.dumps(report,indent=2,sort_keys=True))
