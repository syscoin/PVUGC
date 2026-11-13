#!/usr/bin/env python3
"""R215 small SHA256d source-token test. Synthetic 80-byte headers, NOT Bitcoin consensus evidence."""
import hashlib, json, struct

def H(*a):
    return hashlib.sha256(b'|'.join(a)).digest()
def D(x):
    return hashlib.sha256(hashlib.sha256(x).digest()).digest()
def xor(a,b):
    return bytes(x^y for x,y in zip(a,b))
def header_prefix(seed):
    result=(struct.pack('<I',0x20000000)+H(b'parent',seed)
            +H(b'merkle',seed)+struct.pack('<II',1720000000,0x207fffff))
    assert len(result)==76
    return result
def mine(prefix,k=12,limit=70000,need=4):
    found=[]
    for nonce in range(limit):
        head=prefix+struct.pack('<I',nonce)
        digest=D(head)
        if int.from_bytes(digest,'big') < (1<<(256-k)):
            found.append((head,digest))
            if len(found)==need:
                return found
    raise RuntimeError('insufficient synthetic nonce hits')
def run():
    n=0; templates={}
    for sid in (b'A',b'B'):
        prefix=header_prefix(sid)
        hits=mine(prefix)
        sigma=H(b'frozen',sid)
        # The first SHA256 compression block is exactly this public 64-byte prefix;
        # its compression midstate is deterministic from these known bytes.
        first_blocks={head[:64] for head,_ in hits}
        assert len(first_blocks)==1; n+=1
        common_prefixes={int.from_bytes(d,'big')>>244 for _,d in hits}
        assert common_prefixes=={0}; n+=1
        unique_digests={d for _,d in hits}
        assert len(unique_digests)==len(hits); n+=1
        # A public shared-input pad is computable BEFORE the nonce mining event.
        sealed=xor(sigma,H(b'pad',prefix[:64]))
        assert xor(sealed,H(b'pad',prefix[:64]))==sigma; n+=1
        # For a proof-dependent pad, different valid headers yield different pads,
        # so the first header's ciphertext cannot be used by every witness.
        pads=[H(b'pad',head,d) for head,d in hits]
        assert len(set(pads))==len(pads); n+=1
        frozen=xor(sigma,pads[0])
        assert all(xor(frozen,p)!=sigma for p in pads[1:]); n+=1
        templates[sid.decode()]={'solutions':len(hits),
             'first_nonce':struct.unpack('<I',hits[0][0][-4:])[0],
             'first_digest':hits[0][1].hex()}
    assert header_prefix(b'A')[:64]!=header_prefix(b'B')[:64]; n+=1
    return {'name':'R215_sha256d_small_repro','checks':n,'templates':templates,
       'scope':'SHA256d nonces and public first-block labels only; no authenticated source, release or QPT proof'}
if __name__=='__main__':
    print(json.dumps(run(),sort_keys=True,indent=2))
