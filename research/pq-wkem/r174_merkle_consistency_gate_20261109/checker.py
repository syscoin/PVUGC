#!/usr/bin/env python3
"""Hash-only ORIGINAL-consistency vs precommitted-capability experiment.
This does NOT implement a WKEM and is not QPT security evidence.
"""
import hashlib, json, itertools

def H(tag, *parts):
    s = b'R174' + len(tag).to_bytes(2,'big') + tag
    for p in parts:
        if isinstance(p, int):
            p = p.to_bytes(8, 'big')
        s += len(p).to_bytes(4,'big') + p
    return hashlib.sha256(s).digest()

def leaf(i,b): return H(b'leaf',i,b)
def par(a,b): return H(b'node',a,b)
def xorb(a,b): return bytes(x^y for x,y in zip(a,b))

def tree(bits):
    assert len(bits) and len(bits)&(len(bits)-1)==0
    lvls=[[leaf(i,b) for i,b in enumerate(bits)]]
    while len(lvls[-1])>1:
        curr=lvls[-1];lvls.append([par(curr[j],curr[j+1]) for j in range(0,len(curr),2)])
    return lvls

def proof(lvls,index):
    out=[]
    for level in lvls[:-1]:
        out.append(level[index^1]);index//=2
    return out

def check(root,index,bit,path):
    d=leaf(index,bit)
    for s in path:
        d=par(s,d) if index&1 else par(d,s)
        index//=2
    return d==root

def R(cnf, bits):
    return all(any(bits[abs(lit)-1] == (1 if lit>0 else 0) for lit in clause) for clause in cnf)

def authenticated_eval(root, assignments, paths, cnf):
    if len(assignments)!=len(paths):return None
    if not all(check(root,i,b,paths[i]) for i,b in enumerate(assignments)):
        return None
    return [int(not any(assignments[abs(lit)-1]==(1 if lit>0 else 0) for lit in clause)) for clause in cnf]

def run():
    assertions=0
    n=4
    # Valid assignments include both bits 00, 01, 10, 11 in the unconstrained positions.
    x_true=[[1,2],[-1,2],[-2,3],[2,4]]
    x_false=[[1],[-1]]
    valid=[];bad=[]
    for bits in itertools.product(range(2),repeat=n):
        lv=tree(bits);root=lv[-1][0];paths=[proof(lv,i) for i in range(n)]
        res=authenticated_eval(root,bits,paths,x_true)
        assert res is not None;assert (res==[0]*len(x_true))==R(x_true,bits);assertions+=2
        if R(x_true,bits):valid.append((bits,root,paths))
        else:bad.append((bits,root,paths))
        # Under same authenticated root, a wrong opening for any index must fail.
        for i in range(n):
            assert not check(root,i,1-bits[i],paths[i]);assertions+=1
            wrong=list(bits);wrong[i]^=1
            assert authenticated_eval(root,wrong,paths,x_true) is None;assertions+=1
        assert authenticated_eval(root,bits,paths,x_false)!=[0,0];assertions+=1
    assert len(valid)>1;assertions+=1
    K=H(b'capability',b'precommitted-native-signature-standin')
    first=valid[0][1]
    # Proposed setup outputs ONE ciphertext under first Merkle-witness-root hash.
    D=xorb(K,H(b'root-mask',first))
    full=[xorb(D,H(b'root-mask',r))==K for bits,r,paths in valid]
    assert sum(full)==1;assertions+=1
    # 'Repair' with common public accept residue. Unrestricted raw decryptor can directly produce K.
    common=H(b'constraint-zero', bytes(len(x_true)))
    D0=xorb(K,common)
    bypass=xorb(D0,H(b'constraint-zero',bytes(len(x_true))))
    assert bypass==K;assertions+=1
    # Also a shared setup-public anchor is not a secret when used as pad seed.
    anchor=H(b'anchor',b'known-commitment')
    DA=xorb(K,H(b'anchor-mask',anchor))
    assert xorb(DA,H(b'anchor-mask',anchor))==K;assertions+=1
    # Exponential source-witness table: actual completeness returns for all valid witnesses.
    records={H(b'lookup',r):xorb(K,H(b'root-mask',r)) for bits,r,paths in valid}
    for bits,r,paths in valid:
        assert authenticated_eval(r,bits,paths,x_true)==[0]*len(x_true)
        e=records[H(b'lookup',r)]
        assert xorb(e,H(b'root-mask',r))==K
        assertions+=2
    assert len(records)==len(valid);assertions+=1
    # False instance cannot create an accepted transcript even though EVERY bit-level
    # leaf opening can be valid. Validation is not itself encrypted key-release.
    for bits in itertools.product(range(2),repeat=n):
        lv=tree(bits);r=lv[-1][0];paths=[proof(lv,i) for i in range(n)]
        assert authenticated_eval(r,bits,paths,x_false)!=[0]*len(x_false);assertions+=1
    # All-valid-witness pad collision probability, in ideal independent oracle for distinct roots:
    # 2^(-256*(v-1)); not a QROM simulator or security proof.
    return {'model':'SHA256 concrete Merkle openings; toy Boolean CNF; no real SYS/BTC source',
            'all_assignments':2**n,'accepted_true_witnesses':len(valid),
            'distinct_true_roots':len(set(r for _,r,_ in valid)),
            'accepted_false_witnesses':0,
            'single_root_ciphertext_successes':sum(full),
            'single_root_ciphertext_total_valid_witnesses':len(valid),
            'public_constraint_zero_bypass':bypass==K,
            'public_anchor_bypass':True,
            'enumerated_witness_table_rows':len(records),
            'assertions':assertions,
            'security':'NONE: functionality/negative controls only, no Build poly or QPT reduction'}

if __name__=='__main__': print(json.dumps(run(),indent=2,sort_keys=True))
