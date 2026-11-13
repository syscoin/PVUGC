#!/usr/bin/env python3
"""R180 fixed-root binding demo. Synthetic values; no source or native signature."""
import hashlib, json

def H(tag,*xs,n=32):
    msg=len(tag).to_bytes(2,'big')+tag
    for x in xs: msg+=len(x).to_bytes(4,'big')+x
    return hashlib.sha256(msg).digest()[:n]

def leaf(i,v,n=32): return H(b'leaf',i.to_bytes(2,'big'),v,n=n)
def pair(a,b,n=32): return H(b'node',a,b,n=n)

def tree(values,n=32):
    q=[leaf(i,values[i],n) if i in values else H(b'empty',n=n) for i in range(16)]
    levels=[q]
    for _ in range(4):
        q=[pair(q[j],q[j+1],n) for j in range(0,len(q),2)];levels.append(q)
    return levels

def path(levels,i):
    out=[]
    for q in levels[:-1]:out.append(q[i^1]);i//=2
    return out

def verify(root,i,v,proof,n=32):
    if len(proof)!=4:return False
    z=leaf(i,v,n)
    for sib in proof:
        z=pair(sib,z,n) if i&1 else pair(z,sib,n)
        i//=2
    return z==root

def run():
    a=H(b'child',b'A');b=H(b'child',b'B');i=5
    old=tree({i:a});new=tree({i:b})
    root=old[-1][0];pa=path(old,i)
    assert verify(root,i,a,pa)
    assert not verify(root,i,b,pa)
    assert new[-1][0]!=root
    assert verify(new[-1][0],i,b,path(new,i))
    appended=tree({i:a,9:b})
    assert appended[-1][0]!=root
    assert not verify(root,9,b,path(appended,9))
    for j in range(128):
        # Distinct synthetic parent WorkIDs do not change pure child identity.
        work=H(b'parent',a,j.to_bytes(2,'big'))
        assert len(work)==32 and verify(root,i,a,pa)
        assert not verify(root,i,H(b'other-child',work),pa)
    # Deliberately weak 1-byte hash permits explicit double opening.
    weak=tree({i:b'x'},n=1);p=path(weak,i);r=weak[-1][0]
    other=next(j.to_bytes(2,'big') for j in range(4096)
               if leaf(i,j.to_bytes(2,'big'),1)==leaf(i,b'x',1))
    assert other!=b'x' and verify(r,i,other,p,n=1)
    assert leaf(i,other,1)==leaf(i,b'x',1)
    return {'checks':264,'weak_colliding_value':other.hex(),
      'status':'fixed-root opening excludes unknown replacement absent collision; no key release'}

if __name__=='__main__':print(json.dumps(run(),sort_keys=True))
