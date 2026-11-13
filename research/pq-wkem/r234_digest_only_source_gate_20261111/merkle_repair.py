#!/usr/bin/env python3
"""Synthetic fully enumerated Merkle source/path exercise; NOT a real BTC/SYS verifier.
Check that two genuine fork roots are not two openings to one root, and that
path-derived mask cannot be presealed for unknown future authenticated roots.
"""
import hashlib,json

def H(tag,*args):
    dat=tag.encode()+b'\0'
    for a in args:dat+=len(a).to_bytes(4,'big')+a
    return hashlib.sha256(dat).digest()

def xor(a,b):return bytes(x^y for x,y in zip(a,b))

def leaf(v):return H('source-leaf',v)
def branch(a,b):return H('source-node',a,b)
def root_and_path(leaves,index):
    nodes=[leaf(z) for z in leaves]
    path=[];i=index
    while len(nodes)>1:
        path.append(nodes[i^1])
        nodes=[branch(nodes[j],nodes[j+1]) for j in range(0,len(nodes),2)]
        i//=2
    return nodes[0],path

def verify(root,index,record,path):
    a=leaf(record)
    for sibling in path:
        a=branch(sibling,a) if index&1 else branch(a,sibling)
        index//=2
    return a==root

def bundle(path):
    return b''.join(z for z in path)

def main():
    # Four distinct synthetic records; divergence after common prefix of 2.
    ancestor=b'block-ancestor'
    a=[ancestor,b'common',b'branch-A',b'extension-A']
    b=[ancestor,b'common',b'branch-B',b'extension-B']
    ra,pa=root_and_path(a,2); rb,pb=root_and_path(b,2)
    sigma=H('fixed-cancel',b'slot')
    assert ra!=rb
    assert verify(ra,2,a[2],pa) and verify(rb,2,b[2],pb)
    assert not verify(ra,2,b[2],pb)
    assert not verify(rb,2,a[2],pa)
    # Parent-work variants for SAME child keep that child's identity and
    # the source semantic Merkle root; different PoW wrappers aren't forks.
    work1=H('bitcoin-parent-work',b'nonce-1')
    work2=H('bitcoin-parent-work',b'nonce-2')
    assert work1!=work2 and root_and_path(a,2)[0]==ra
    # A path-to-key mask frozen for the known source root opens for known A,
    # not for the as-yet-unknown future fork path B.
    seal=xor(sigma,H('path-derived-pad',bundle(pa)))
    assert xor(seal,H('path-derived-pad',bundle(pa)))==sigma
    assert xor(seal,H('path-derived-pad',bundle(pb)))!=sigma
    # Repair by using the common public anchor instead: early release.
    anchor=H('public-anchor',ancestor)
    public_seal=xor(sigma,H('public-anchor-pad',anchor))
    assert xor(public_seal,H('public-anchor-pad',anchor))==sigma
    # Repair by a public instruction to check Merkle path: it can reject
    # wrong-root data, but an attacker can execute public code without making
    # this check control the secret algebraically.
    checked_A=verify(ra,2,a[2],pa)
    checked_B=verify(rb,2,b[2],pb)
    assert checked_A and checked_B
    # Note a valid fork between two different roots requires NO hash collision.
    return {'candidate':'R234-two-root-merkle-repair',
       'synthetic_valid_root_A':ra.hex(),'synthetic_valid_root_B':rb.hex(),
       'same_position_openings_against_other_root_rejected':True,
       'work_wrappers_do_not_change_source_child':True,
       'presealed_A_path_does_not_decode_B':True,
       'public_anchor_mask_revealed_early':True,
       'original_proof_and_key_release':'NOT IMPLEMENTED',
       'hash_algorithm':'SHA-256 with synthetic domain tags',
       'checks':9,
       'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__':print(json.dumps(main(),indent=2,sort_keys=True))
