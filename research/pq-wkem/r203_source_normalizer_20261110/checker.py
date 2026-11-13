#!/usr/bin/env python3
"""R203: Merkle-root PREIMAGE shared-pad experiment.

Not a BTC/SYS implementation or a hash-only original-evidence WKEM.
All source leaf/preimage data in this fixture is controlled by the builder.
"""
import hashlib
import json

def H(tag, *xs):
    m = len(tag).to_bytes(2,'big')+tag
    for x in xs:
        m += len(x).to_bytes(4,'big')+x
    return hashlib.sha256(m).digest()

def X(a,b):return bytes(x^y for x,y in zip(a,b))

def build_tree(seed):
    leaves=[H(b'leaf', seed,bytes([i])) for i in range(4)]
    a=H(b'node',leaves[0],leaves[1]);b=H(b'node',leaves[2],leaves[3])
    return leaves,(a,b),H(b'node',a,b)

def proof(leaves,index):
    a=H(b'node',leaves[0],leaves[1]);b=H(b'node',leaves[2],leaves[3])
    return [leaves[index^1], b if index<2 else a]

def verified_root_pair(root,index,leaf,path):
    if len(path)!=2 or index not in range(4):return None
    n=H(b'node',leaf,path[0]) if index%2==0 else H(b'node',path[0],leaf)
    pair=(n,path[1]) if index<2 else (path[1],n)
    return pair if H(b'node',*pair)==root else None

def run():
    stats={k:0 for k in ('all_four_proofs_same_key','wrong_leaf_not_open','wrong_sibling_not_open','public_proof_opens_even_without_fork','source_builder_opens_early','public_root_pad_opens_without_path','different_tree_roots_not_same_key','public_root_pair_leaks_from_first_proof','two_history_masks_disagree_for_valid_alternatives')}
    for i in range(64):
        seed=i.to_bytes(4,'big')
        leaves,top,root=build_tree(seed)
        ctx=H(b'ctx',seed)
        sigma=H(b'frozen-cancel',seed)
        pad=H(b'pad',ctx,*top)
        E=X(sigma,pad)
        for j in range(4):
            path=proof(leaves,j)
            got=verified_root_pair(root,j,leaves[j],path)
            assert got==top
            assert X(E,H(b'pad',ctx,*got))==sigma
            stats['all_four_proofs_same_key']+=1
            altered_leaf=H(b'forged-leaf',seed,bytes([j]))
            assert verified_root_pair(root,j,altered_leaf,path) is None
            stats['wrong_leaf_not_open']+=1
            altered_path=[H(b'forged-sibling',seed,bytes([j])),path[1]]
            assert verified_root_pair(root,j,leaves[j],altered_path) is None
            stats['wrong_sibling_not_open']+=1
        # An ordinary membership proof (not an ORIGINAL fork/PoB/BTC-work fault)
        # reveals BOTH children of root and hence the full frozen capability.
        got=verified_root_pair(root,0,leaves[0],proof(leaves,0))
        assert got==top and X(E,H(b'pad',ctx,*got))==sigma
        stats['public_proof_opens_even_without_fork']+=1
        # Any builder/source retaining top knows the release value immediately.
        assert X(E,H(b'pad',ctx,*top))==sigma
        stats['source_builder_opens_early']+=1
        # A root-output-only normalization would be publicly decodable.
        E_public=X(sigma,H(b'pad-public',ctx,root))
        assert X(E_public,H(b'pad-public',ctx,root))==sigma
        stats['public_root_pad_opens_without_path']+=1
        other_leaves,other_top,other_root=build_tree(seed+b'other')
        assert other_root!=root and other_top!=top
        assert X(E,H(b'pad',ctx,*other_top))!=sigma
        stats['different_tree_roots_not_same_key']+=1
        # The first ordinary path leaks top by computing its upper child plus sibling.
        assert top==verified_root_pair(root,2,leaves[2],proof(leaves,2))
        stats['public_root_pair_leaks_from_first_proof']+=1
        # Attempt to repair early opening by requiring a second, future fork root.
        # Setup can seal using one guessed future fork, but another valid future
        # root necessarily changes the pad; this does NOT assert real mining.
        B1=build_tree(seed+b'fork-1')[1]
        B2=build_tree(seed+b'fork-2')[1]
        E2=X(sigma,H(b'pair-source-pad',ctx,*top,*B1))
        assert B1!=B2
        assert X(E2,H(b'pair-source-pad',ctx,*top,*B2))!=sigma
        stats['two_history_masks_disagree_for_valid_alternatives']+=1
    return {"run":"R203-MASH-20261110","scope":"restricted Merkle-correlation correctness + early-release counterexamples; no ORIGINAL WE", "groups":stats,"assertions":sum(stats.values()),"sha256_source":hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
