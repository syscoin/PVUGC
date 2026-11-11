"""R221: SHA256d source commitment does not open its SHA256 preimage.
Synthetic 80-byte headers and intentionally truncated toy commitments only.
No ORIGINAL BTC/SYS verifier, witness-KEM or quantum security experiment.
"""
import hashlib, json, struct

def H(b): return hashlib.sha256(b).digest()
def HD(b): return H(H(b))
def C(ctx,k): return H(b'R221/commit'+ctx+k)
def X(a,b): return bytes(x^y for x,y in zip(a,b))
def header(q,ctx,nonce,bits=0x1f3fffff):
    cb=HD(b'coinbase:'+q)
    sib=HD(b'second-tx:'+ctx)
    root=HD(cb+sib)
    return struct.pack('<I',0x20000000)+H(b'anchor'+ctx)+root+struct.pack('<III',1700000000,bits,nonce)

def run():
    counts={'path_auth_without_k':0,'public_q_pad_early':0,'plaintext_k_early':0,
            'toy_collision_same_mined_proof':0}
    for i in range(16):
        ctx=H(b'claim'+i.to_bytes(2,'big'))
        k1=H(b'secret1'+ctx)
        q=C(ctx,k1)
        root=HD(HD(b'coinbase:'+q)+HD(b'second-tx:'+ctx))
        assert root==header(q,ctx,0)[36:68]
        counts['path_auth_without_k']+=1
        sigma=H(b'cancel-signature-fixture'+ctx)
        # If pad key is q, the signature is available from the public capsule.
        d=X(sigma,H(b'pad'+q)); assert X(d,H(b'pad'+q))==sigma
        counts['public_q_pad_early']+=1
        # If the source literally publishes k1, no R3 fork is needed to open.
        d=X(sigma,H(b'pad'+k1)); assert X(d,H(b'pad'+k1))==sigma
        counts['plaintext_k_early']+=1
        # 12-bit deliberately TRUNCATED commitment; NOT a SHA256 break.
        def short(k): return (int.from_bytes(C(ctx,k)[:2],'big')>>4).to_bytes(2,'big')
        t=short(k1)
        k2=next(H(b'candidate'+ctx+j.to_bytes(4,'big')) for j in range(100000)
                if short(H(b'candidate'+ctx+j.to_bytes(4,'big')))==t)
        assert k1!=k2 and short(k2)==t
        bits=0x1f3fffff; target=(bits&0x007fffff)<<(8*((bits>>24)-3))
        nonce=next(n for n in range(1<<20)
                   if int.from_bytes(HD(header(t,ctx,n)),'little')<=target)
        assert header(short(k1),ctx,nonce)==header(short(k2),ctx,nonce)
        counts['toy_collision_same_mined_proof']+=1
    return {'run':'R221-SCOM-mini','checks':sum(counts.values()),'groups':counts,
            'scope':'Synthetic source commitment only; not original proof or QPT security'}

if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
