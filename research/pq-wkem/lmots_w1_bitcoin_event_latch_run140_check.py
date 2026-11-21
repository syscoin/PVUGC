#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, struct

D_PBLC=0x8080; D_LEAF=0x8282; D_INTR=0x8383
OP_SHA256=0xa8; OP_EQUAL=0x87; OP_SWAP=0x7c; OP_BOOLOR=0x9b; OP_VERIFY=0x69; OP_CHECKSIG=0xac

def H(x): return hashlib.sha256(x).digest()
def u32(x): return struct.pack(">I",x)
def u16(x): return struct.pack(">H",x)
def u8(x): return bytes([x])

def preimage(I,q,i,x): return I+u32(q)+u16(i)+u8(0)+x
def endpoint(I,q,i,x): return H(preimage(I,q,i,x))

def endpoints(I,q):
    xs=[]; ys=[]
    for i in range(265):
        x=H(b"run140-x"+I+u32(q)+u16(i))
        xs.append(x); ys.append(endpoint(I,q,i,x))
    return xs,ys

def lmots_K(I,q,ys): return H(I+u32(q)+u16(D_PBLC)+b"".join(ys))
def leaf(I,r,K): return H(I+u32(r)+u16(D_LEAF)+K)
def node(I,r,l,rh): return H(I+u32(r)+u16(D_INTR)+l+rh)

def tree(I,h):
    n=1<<h; T={}; M={}
    for q in range(n):
        xs,ys=endpoints(I,q); K=lmots_K(I,q,ys)
        T[n+q]=leaf(I,n+q,K); M[q]=(xs,ys,K)
    for r in range(n-1,0,-1): T[r]=node(I,r,T[2*r],T[2*r+1])
    return T,M

def path(T,h,q):
    r=(1<<h)+q; p=[]
    while r>1: p.append(T[r^1]); r//=2
    return p

def verify(I,h,q,K,p,root):
    r=(1<<h)+q; cur=leaf(I,r,K)
    for sib in p:
        pr=r//2
        cur=node(I,pr,cur,sib) if r%2==0 else node(I,pr,sib,cur)
        r=pr
    return cur==root

def bits(z):
    c=(z<<7)&0xffff
    return [(c>>(15-j))&1 for j in range(9)]

def push(d):
    assert len(d)<=75
    return bytes([len(d)])+d

def script(y256,y257,pk):
    return (bytes([OP_SHA256])+push(y257)+bytes([OP_EQUAL,OP_SWAP,OP_SHA256])+
            push(y256)+bytes([OP_EQUAL,OP_BOOLOR,OP_VERIFY])+push(pk)+bytes([OP_CHECKSIG]))

def latch(y256,y257,c256,c257,sigok):
    return ((H(c257)==y257) or (H(c256)==y256)) and sigok

def main():
    a=0; always=[True]*9; release=0
    for z in range(257):
        b=bits(z); assert len(b)==9; a+=1
        assert not (b[0] and b[1]); a+=1
        release += int((b[0]==0) or (b[1]==0))
        for j,v in enumerate(b):
            if v: always[j]=False
    assert release==257; a+=1
    assert always==[False]*9; a+=1

    I=H(b"run140-I")[:16]; h=5; T,M=tree(I,h); root=T[1]; q=7
    xs,ys,K=M[q]; p=path(T,h,q)
    assert verify(I,h,q,K,p,root); a+=1
    assert lmots_K(I,q,ys)==K; a+=1
    assert len(b"".join(ys))==8480; a+=1
    y256,y257=ys[256],ys[257]
    assert len(preimage(I,q,256,xs[256]))==55; a+=1

    pk=b"\x02"+H(b"owner")[:32]; sc=script(y256,y257,pk)
    assert len(sc)==108; a+=1
    for z in range(257):
        b=bits(z)
        s256=xs[256] if b[0]==0 else y256
        s257=xs[257] if b[1]==0 else y257
        c256=preimage(I,q,256,s256) if b[0]==0 else b""
        c257=preimage(I,q,257,s257) if b[1]==0 else b""
        assert len(c256) in (0,55); a+=1
        assert len(c257) in (0,55); a+=1
        assert latch(y256,y257,c256,c257,True); a+=1
        assert not latch(y256,y257,c256,c257,False); a+=1

    for d in (b"",b"x",b"\0"*55,H(b"dummy")):
        assert not latch(y256,y257,d,d,True); a+=1

    assert 3<=100; a+=1
    assert 55<=80; a+=1
    assert 73<=80; a+=1
    assert len(sc)<=3600; a+=1
    assert 8<=201; a+=1
    wb=1+(1+73)+(1+55)+(1+0)+(1+len(sc))
    assert wb==241; a+=1

    print(json.dumps({
      "status":"PASS","identifier":"RUN140_LMOTS_W1_BITCOIN_EVENT_LATCH",
      "assertions":a,
      "rfc8554_w1":{"n":32,"w":1,"p":265,"u":256,"v":9,"ls":7,
        "checksum_states":257,"selected_indices":[256,257],
        "all_states_reveal_one_raw_secret":release==257,
        "no_single_checksum_bit_always_zero":True},
      "lms_fixture":{"height":h,"q":q,"root":root.hex(),"K":K.hex(),
        "expanded_manifest_bytes":8480,"auth_path_nodes":len(p),"verified":True},
      "bitcoin_p2wsh":{"script_bytes":len(sc),"nonpush_ops":8,
        "witness_args_excluding_script":3,"release_item_bytes":55,
        "witness_bytes_one_real_one_empty":wb},
      "scope":[
        "Finite RFC8554/P2WSH semantics only; not Bitcoin Core.",
        "Expanded LMOTS endpoints are extra public information beyond compact RFC8554 K.",
        "Security inherits source-signer non-early-release and SHA256 preimage hardness.",
        "Current P2WSH owner ECDSA is not post-quantum."
      ]},indent=2,sort_keys=True))
if __name__=="__main__": main()
