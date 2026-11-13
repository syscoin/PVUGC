#!/usr/bin/env python3
"""Exact table-family repair of source-occurrence mixing, and future-certificate gap.
Finite toy: two known false source certificates, one future true certificate.
Not a proof of impossibility for every hash-only WKEM construction.
"""
import hashlib, json

def H(tag,*parts):
    h=hashlib.sha256(tag.encode()+b'\0')
    for p in parts:
        if isinstance(p,str):p=p.encode()
        if isinstance(p,int):p=p.to_bytes(4,'big')
        h.update(len(p).to_bytes(4,'big')+p)
    return h.digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))

def run():
    checks=0
    for seed in range(100):
        ctx=H('claim',seed)
        K=H('frozen-cancel-signature-stub',ctx)
        # Catalogued, whole source records with no satisfying record.
        known={b'cert-A':(1,0),b'cert-B':(0,1)}
        true_future={b'cert-C':(1,1)}
        rows={}
        labels={}
        for cert,bits in known.items():
            labels[cert]=H('label',ctx,cert)
            # A and B are false; do not encrypt the true cancellation key.
            rows[cert]=H('unrelated-false-row',ctx,cert)
        # Requesting input labels from different sources gives no matching
        # single-source row; correctness of this simple security property is
        # by lookup, not a QPT claim or general security theorem.
        assert b'cert-C' not in rows
        assert all(not (bits[0] and bits[1]) for bits in known.values())
        checks+=2
        # A future authentic certificate C with (1,1) has no row, so the
        # fixed two-entry table fails all-witness completeness.
        assert b'cert-C' in true_future and b'cert-C' not in rows
        checks+=1
        # Precomputing a row for C repairs correctness for C but reveals
        # K immediately if its label and row are public before mining.
        future_label=H('label',ctx,b'cert-C')
        future_row=xor(K,H('pad',ctx,future_label))
        assert xor(future_row,H('pad',ctx,future_label))==K
        checks+=1
        # A seed-keyed label can hide K but the publicly available source
        # certificate C itself does not contain the independent secret seed.
        secret=H('builder-only-secret',ctx)
        keyed_label=H('private-label',secret,ctx,b'cert-C')
        assert keyed_label!=future_label
        checks+=1
    return {'run':'R224-GLOBAL-SOURCE-REPAIR','assertions':checks,
        'result':'whole-certificate binding defeats input occurrence mixing in a fixed finite catalog, but either misses unanticipated future certificates or publishes their opening prematurely',
        'scope':'restricted explicit-row family only, no general impossibility or cryptographic source-bound release',
        'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}
if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
