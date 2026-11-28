"""Fixed-txid/different-assertion cancellation portability; NOT source or WE validation."""
import hashlib, struct, json
H=lambda b:hashlib.sha256(hashlib.sha256(b).digest()).digest()
U=lambda n:struct.pack('<I',n)
V=lambda n:bytes((n,))
def tx(witness,script,claim_in_base=False):
    vin=V(1)+(b'P'*32)+U(0)+V(0)+U(0xfffffffe)
    outputs=[struct.pack('<Q',9000)+V(len(script))+script]
    if claim_in_base:
        c=b'\x6a\x20'+hashlib.sha256(witness).digest()
        outputs.append(struct.pack('<Q',0)+V(len(c))+c)
    body=U(2)+vin+V(len(outputs))+b''.join(outputs)
    base=body+U(0)
    full=U(2)+b'\x00\x01'+body[4:]+V(1)+V(len(witness))+witness+U(0)
    return H(base),H(full),base

def run():
    checks=0
    for i in range(32):
        script=b'\x51\x20'+H(U(i))
        w0=b'NOTARY:valid-burn:'+U(i);w1=b'NOTARY:absent-burn:'+U(i)
        t0,h0,_=tx(w0,script);t1,h1,_=tx(w1,script)
        assert t0==t1;checks+=1
        assert h0!=h1;checks+=1
        m0=H(b'CANCEL'+t0+U(0)+script);m1=H(b'CANCEL'+t1+U(0)+script)
        assert m0==m1;checks+=1
        # CONDITIONAL: if a source-admitted w1 fault opens a frozen cancel sig,
        # it is also a valid sig for the identical m0 on the w0 history.
        R2_w0=False;R2_w1=True;admits_w1=True
        assert not R2_w0 and R2_w1 and admits_w1 and m0==m1;checks+=1
        # A source rule excluding the alternate branch blocks that opening.
        admits_w1=False
        assert not (R2_w1 and admits_w1);checks+=1
        # Claim-specific nonwitness output separates outpoints and sighashes.
        c0,_,_=tx(w0,script,True);c1,_,_=tx(w1,script,True)
        assert c0!=c1;checks+=1
        assert H(b'CANCEL'+c0+U(0)+script)!=H(b'CANCEL'+c1+U(0)+script);checks+=1
    return {'id':'R225-short','checks':checks,'seeds':32,'limitation':'synthetic source-admission booleans; no real PoW/AuxPoW, native signature, Build/Open, or QPT security'}
if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
