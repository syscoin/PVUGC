#!/usr/bin/env python3
"""R224: source input-label delivery toy, NOT ORIGINAL WKEM or actual AuxPoW.
All source data are abstract public certificates; no source admission is claimed.
Tests only exact classical full-public access / completeness behavior.
"""
import hashlib
import json
from collections import Counter

def H(t,*xs):
    h=hashlib.sha256()
    t=t if isinstance(t,bytes) else t.encode()
    h.update(len(t).to_bytes(2,'big')+t)
    for x in xs:
        if isinstance(x,int):x=x.to_bytes(4,'big')
        if isinstance(x,str):x=x.encode()
        h.update(len(x).to_bytes(4,'big')+x)
    return h.digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))

counts=Counter()
def ck(test,label):
    assert test,label
    counts[label]+=1

def run():
    for seed in range(100):
        ctx=H('claim',seed)
        K=H('native-signature-stub',ctx)
        # A: Public semantic-bit label. Any hostile caller computes it without a source.
        L1=H('public-bit-label',ctx,0,1)
        E=xor(K,H('pad',ctx,L1))
        K_early=xor(E,H('pad',ctx,H('public-bit-label',ctx,0,1)))
        ck(K_early==K,'public_bit_label_early_key')

        # B: Full-certificate-derived label; build knows only one certificate.
        # Non-mined certificates are just domain strings, not valid BTC headers.
        c0=H('future-certificate',ctx,seed,0)
        c1=H('future-certificate',ctx,seed,1)
        L0=H('cert-input-label',ctx,c0)
        L1_future=H('cert-input-label',ctx,c1)
        E0=xor(K,H('pad',ctx,L0))
        ck(xor(E0,H('pad',ctx,L0))==K,'single_preselected_certificate_opens')
        ck(xor(E0,H('pad',ctx,L1_future))!=K,'later_distinct_certificate_not_same_key')

        # C: Published mask under a source-independent public hash pad.
        L_hidden=H('private-label',seed,ctx)
        label_ct=xor(L_hidden,H('input-public-pad',ctx,0,1))
        recovered=xor(label_ct,H('input-public-pad',ctx,0,1))
        ck(recovered==L_hidden,'public_mask_leaks_both_labels')

        # D: Private seed masks label. Honest opener cannot derive it from source
        # alone; revealing seed restores early availability.
        secret_seed=H('private-seed',ctx,seed)
        label_ct=xor(L_hidden,H('input-secret-pad',secret_seed,ctx,0,1))
        early=xor(label_ct,H('input-secret-pad',secret_seed,ctx,0,1))
        ck(early==L_hidden,'revealed_secret_seed_leaks_label')
        # At fixed 256-bit hash output the correct pad is not given by source.
        ck(H('input-secret-pad',secret_seed,ctx,0,1)!=H('input-public-pad',ctx,0,1),
           'source_certificate_does_not_supply_hidden_seed')

        # E: A public post-label certificate validity check does not constrain
        # a hostile evaluator of the independently readable encrypted row.
        cert_valid=False
        ck(not cert_valid and xor(E,H('pad',ctx,H('public-bit-label',ctx,0,1)))==K,
           'postcheck_bypass')

        # F: occurrence mixing: neither authenticated record individually has
        # (bit0,bit1)=(1,1), but independently usable labels for each occurrence
        # provide the forbidden pair. This is a *synthetic* original predicate.
        A=(1,0);B=(0,1)
        ck(not (A[0]&A[1]) and not (B[0]&B[1]),'no_single_qualifying_record')
        u=H('garbled-source-input',ctx,0,1)
        v=H('garbled-source-input',ctx,1,1)
        row=xor(K,H('accepted-two-inputs',ctx,u,v))
        # A discloses u; B discloses v; labels are from different source records.
        ck(xor(row,H('accepted-two-inputs',ctx,u,v))==K,
           'cross_source_occurrence_mixing_opens_key')

        # Domain separation prevents cross-claim mixing, not same-claim mixing.
        ctx2=H('another-claim',seed)
        v2=H('garbled-source-input',ctx2,1,1)
        ck(xor(row,H('accepted-two-inputs',ctx,u,v2))!=K,
           'claim_context_domain_separation_only')

        # Universal N-of-N cancellation: N-1 participants retaining native
        # stubs plus an exposed honest h gate is still enough for early release.
        sigs=[H('party-signature-stub',ctx,i) for i in range(4)]
        honest=sigs[-1]
        honest_L=H('public-bit-label',ctx,3,1)
        honest_C=xor(honest,H('pad',ctx,honest_L))
        unauthorized_h=xor(honest_C,H('pad',ctx,H('public-bit-label',ctx,3,1)))
        ck(unauthorized_h==honest and len(sigs[:-1]+[unauthorized_h])==4,
           'n_of_n_cannot_fix_public_label')
    return {'run':'R224-SOURCE-LABEL-DELIVERY-20261111',
            'assertions':sum(counts.values()),'groups':dict(sorted(counts.items())),
            'scope':'synthetic public-label availability, witness mixing and completeness ONLY; no genuine source, native sig, WKEM or QPT tests',
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__':
    print(json.dumps(run(),sort_keys=True,indent=2))
