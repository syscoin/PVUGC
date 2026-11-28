#!/usr/bin/env python3
"""R229 minimal DA-coverage countercheck; synthetic, not Bitcoin/Syscoin consensus."""
import hashlib, json

def H(*parts):
    h=hashlib.sha256()
    for p in parts:
        b=str(p).encode()
        h.update(len(b).to_bytes(4,'big')+b)
    return h.digest()

def node(a,b):return H('node',a.hex(),b.hex())
def leaf(s):return H('leaf',s)

def root4(entries):
    a=[leaf(s) for s in entries]
    return node(node(a[0],a[1]),node(a[2],a[3]))

def membership(entries,index):
    a=[leaf(s) for s in entries]
    if index<2:return [a[index^1],node(a[2],a[3])]
    return [a[index^1],node(a[0],a[1])]

def verify(root,entry,index,path):
    x=leaf(entry)
    for sibling in path:
        x=node(x,sibling) if index%2==0 else node(sibling,x)
        index//=2
    return x==root

def finder(public,baseline):
    for entry in public.values():
        if entry.startswith('qualified:') and entry!=baseline:
            return entry
    return None

def main():
    entries=['qualified:baseline','metadata','qualified:conflict','metadata2']
    root=root4(entries)
    disclosed={0:entries[0],1:entries[1],3:entries[3]}
    assert all(verify(root,v,i,membership(entries,i)) for i,v in disclosed.items())
    assert verify(root,entries[2],2,membership(entries,2))
    assert finder(disclosed,entries[0]) is None
    assert finder({**disclosed,2:entries[2]},entries[0])==entries[2]
    assert not verify(root,'qualified:forgery',2,membership(entries,2))
    return {'assertions':5,'finding':'Merkle commitment does not imply full public witness enumeration',
            'scope':'synthetic source, no original consensus verifier, no Build/Open'}

if __name__=='__main__':print(json.dumps(main(),sort_keys=True,indent=2))
