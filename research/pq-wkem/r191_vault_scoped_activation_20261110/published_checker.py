#!/usr/bin/env python3
"""R191 published minimal checker: SegWit fixed txid, variable witness, claim binding.
Synthetic header and source roots. No PoW, signature security or key-release gate.
"""
import hashlib,json,struct
H=lambda b:hashlib.sha256(b).digest()
D=lambda b:H(H(b))

def cs(n):
    return bytes([n]) if n<253 else b'\xfd'+struct.pack('<H',n) if n<65536 else b'\xfe'+struct.pack('<I',n)
def data(b):return cs(len(b))+b

def tx(prev,outputs,witness=None):
    s=struct.pack('<I',2)+(b'\x00\x01' if witness is not None else b'')
    s+=b'\x01'+prev+struct.pack('<I',0)+b'\x00'+struct.pack('<I',0xfffffffe)
    s+=cs(len(outputs))
    for value,script in outputs:s+=struct.pack('<Q',value)+data(script)
    if witness is not None:s+=cs(len(witness))+b''.join(data(w) for w in witness)
    return s+b'\0'*4

def signclaim(seed,claim,base_id):
    # Functional 256-bit Lamport OTS; no re-use allowed for production.
    private=[(H(seed+b'0'+bytes([i])),H(seed+b'1'+bytes([i]))) for i in range(256)]
    public=[(H(a),H(b)) for a,b in private]
    bits=H(b'claim|'+base_id+claim)
    sig=b''.join(private[i][(bits[i//8]>>(7-i%8))&1] for i in range(256))
    return public,sig

def validclaim(public,claim,base_id,sig):
    if len(sig)!=8192:return False
    bits=H(b'claim|'+base_id+claim)
    return all(H(sig[32*i:32*(i+1)])==public[i][(bits[i//8]>>(7-i%8))&1] for i in range(256))

def blockroot(txid,wtxid):
    reserved=H(b'reserved')
    commit=D(D(bytes(32)+wtxid)+reserved)
    coinbase=tx(bytes(32),[(0,b'\x6a\x24\xaa\x21\xa9\xed'+commit)])
    cbid=D(coinbase)
    return D(cbid+txid),commit,reserved

def main():
    n=0
    def ck(value):
        nonlocal n
        assert value
        n+=1
    vault=H(b'vault')
    out=[(300000,b'\x51\x20'+H(b'fixed-escrow'))]
    base=tx(vault,out)
    tid=D(base)
    claimA=b'claim-A:vault='+vault
    claimB=b'claim-B:vault='+vault
    pub,sA=signclaim(b'notary-seed',claimA,tid)
    _,sB=signclaim(b'notary-seed',claimB,tid) # deliberate OTS reuse in synthetic fixture
    a=b'\x50'+data(claimA)+data(sA)
    b=b'\x50'+data(claimB)+data(sB)
    witA=tx(vault,out,[b'spend-sig-placeholder',a])
    witB=tx(vault,out,[b'spend-sig-placeholder',b])
    wa,wb=D(witA),D(witB)
    ck(D(base)==tid and wa!=wb)
    ck(validclaim(pub,claimA,tid,sA) and validclaim(pub,claimB,tid,sB))
    ck(not validclaim(pub,claimB,tid,sA))
    ck(not validclaim(pub,claimA,D(tx(H(b'other-vault'),out)),sA))
    rootA,commitA,res=blockroot(tid,wa)
    rootB,commitB,_=blockroot(tid,wb)
    ck(rootA!=rootB and commitA!=commitB)
    for w in (wa,wb):
        root,commit,res=blockroot(tid,w)
        ck(commit==D(D(bytes(32)+w)+res))
        ck(root==blockroot(tid,w)[0])
        ck(commit!=D(D(bytes(32)+H(b'bad-witness'))+res))
    cancel=lambda t,o,d:H(b'cancel|'+t+struct.pack('<I',o)+d)
    refund=H(b'refund')
    ck(cancel(D(base),0,refund)==cancel(tid,0,refund))
    ck(cancel(tid,1,refund)!=cancel(tid,0,refund))
    ck(cancel(tid,0,H(b'other-refund'))!=cancel(tid,0,refund))
    ck(D(tx(vault,[(300000,b'other-script')]))!=tid)
    return {'run':'R191-MINIMAL-20261110','checks':n,'fixed_txid':tid.hex(),
            'wtxid_A':wa.hex(),'wtxid_B':wb.hex(),
            'result':'witness-dependent claim authenticates under variant block commitment, while child spends same txid',
            'limitations':'synthetic witness and coinbase, no PoW/native signature/WE/QPT; OTS reuse in fixture'}
if __name__=='__main__':print(json.dumps(main(),sort_keys=True,indent=2))
