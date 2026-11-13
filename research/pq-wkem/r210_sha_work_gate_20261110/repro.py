"""R210 exact small reproduction: SHA256d headers, synthetic work ONLY, no WKEM."""
import hashlib,struct,json

def H(*x):
    return hashlib.sha256(b''.join(len(a).to_bytes(4,'big')+a for a in x)).digest()
def D(x):
    return hashlib.sha256(hashlib.sha256(x).digest()).digest()
def X(a,b):
    return bytes(v^w for v,w in zip(a,b))
def hdr(seed,nonce):
    return struct.pack('<I32s32sIII',0x20000000,H(b'anchor',seed),H(b'auxpow-merkle',seed),1700000000,0x207fffff,nonce)
def test(seed):
    heads=[hdr(seed,n) for n in range(2048)]
    valid=[(v,D(v)) for v in heads if int.from_bytes(D(v),'little')>>(256-3)==0]
    assert len(valid)>4
    K=H(b'precommitted-K',seed)
    public_prefix=b'\x00'
    E=X(K,H(b'prefix-pad',seed,public_prefix))
    assert all(X(E,H(b'prefix-pad',seed,bytes([int.from_bytes(d,'little')>>(256-3)])))==K for _,d in valid)
    # Raw capsule recovery without header, PoW, source, or verifier call:
    assert X(E,H(b'prefix-pad',seed,public_prefix))==K
    # Binding to a single actual header instead removes universal correctness:
    E2=X(K,H(b'full-header-pad',seed,*valid[0]))
    wrong=sum(X(E2,H(b'full-header-pad',seed,v,d))!=K for v,d in valid[1:])
    assert wrong==len(valid)-1
    return {'qualifying':len(valid),'unauthorized_early_open':True,'other_header_failures':wrong}

if __name__=='__main__':
    print(json.dumps({'run':'R210_SHA_WORK_GATE_SMALL','toy_target_bits':3,
     'results':[test(i.to_bytes(1,'big')) for i in range(2)],
     'note':'Source SHA256d executed; no real AuxPoW, DAA, best-chain, or WE.'},sort_keys=True))
