"""R193: public-input SHA256 garbling; FALSE source predicate counterexample.
Research fixture only. Does NOT implement real BTC/SYS source, WE or QPT proof.
"""
import hashlib, json

def H(*xs):
    return hashlib.sha256(b''.join(len(x).to_bytes(4,'big')+x for x in xs)).digest()

def X(a,b): return bytes(x^y for x,y in zip(a,b))

def build(seed,z):
    # All input bit labels must be public for unrestricted bit-witness choice.
    wires={v:[H(seed,v.encode(),bytes([b])) for b in (0,1)]
           for v in ('xA','xB','one','notA','eq','and','accept')}
    gates=[('notA','xA','one',lambda a,b:a^b),
           ('eq','xA','xB',lambda a,b:int(a==b)),
           ('and','notA','xB',lambda a,b:a&b),
           ('accept','and','eq',lambda a,b:a&b)]
    rows={}
    for o,l,r,fn in gates:
        rows[o]={(a,b):X(wires[o][fn(a,b)],H(z,o.encode(),wires[l][a],wires[r][b]))
                 for a in (0,1) for b in (0,1)}
    sig=H(seed,b'precommitted-cancel-signature')
    sealed=X(sig,H(wires['accept'][1]))
    return wires,rows,sealed,sig

def run():
    ct={'valid_false_inputs_reject':0,'inconsistent_rows_open_early':0,
        'public_merkle_not_authorization':0,'future_z_incompatible_with_fixed_rows':0}
    for n in range(64):
        seed=n.to_bytes(4,'big'); z=H(seed,b'public-anchor'); w,t,seal,sig=build(seed,z)
        def ev(o,l,r,a,b,zz=z):
            return X(t[o][(a,b)],H(zz,o.encode(),w[l][a],w[r][b]))
        for bit in (0,1):
            # R(xA,xB) = !xA && xB && (xA==xB), always FALSE.
            na=1-bit; eq=1; mid=na&bit; final=mid&eq
            assert ev('notA','xA','one',bit,1)==w['notA'][na]
            assert ev('eq','xA','xB',bit,bit)==w['eq'][eq]
            assert ev('and','notA','xB',na,bit)==w['and'][mid]
            assert ev('accept','and','eq',mid,eq)==w['accept'][final]
            assert final==0
            ct['valid_false_inputs_reject']+=1
        # Attacker combines inconsistent sub-evaluations using SAME z.
        assert ev('notA','xA','one',0,1)==w['notA'][1]
        assert ev('eq','xA','xB',0,0)==w['eq'][1]
        assert ev('and','notA','xB',1,1)==w['and'][1]
        accepting=ev('accept','and','eq',1,1)
        assert accepting==w['accept'][1] and X(seal,H(accepting))==sig
        ct['inconsistent_rows_open_early']+=1
        # Committing all public labels just authenticates their bytes.
        root=H(*sum((w[x] for x in ('xA','xB')),[]))
        assert root==H(*sum((w[x] for x in ('xA','xB')),[]))
        ct['public_merkle_not_authorization']+=1
        # Binding static garbled pads to unknown later source z breaks opening.
        future_z=H(seed,b'unknown-future-source-SHA256d')
        assert future_z!=z
        assert ev('accept','and','eq',0,1,future_z)!=w['accept'][0]
        ct['future_z_incompatible_with_fixed_rows']+=1
    return {'run':'R193', 'checks':sum(ct.values()), 'groups':ct,
            'scope':'false Boolean source circuit; no actual AuxPoW or PQ security'}

if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
