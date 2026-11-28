#!/usr/bin/env python3
"""R214 one-sided source label bootstrap: bounded functional falsification only.

No real AuxPoW, source authentication, miner-issued labels, native PQ
signature, KEM, or QPT security experiment is implemented.
"""
import hashlib, json
from collections import Counter

def h(domain, *parts):
    buf = len(domain).to_bytes(4,'big') + domain
    for x in parts: buf += len(x).to_bytes(4,'big')+x
    return hashlib.sha256(buf).digest()

def xo(a,b):return bytes(i^j for i,j in zip(a,b))

counts=Counter()
def ck(expr, label):
    if not expr:raise AssertionError(label)
    counts[label] += 1

def run():
    for seed in range(96):
        s=seed.to_bytes(4,'big')
        x=h(b'claim',s)
        u0=h(b'baseline-pure-child', x)
        u1=h(b'qualified-future-A', x)
        u2=h(b'qualified-future-B', x)
        uf=h(b'fabricated-unauthenticated',x)
        sigma=h(b'frozen-cancel-signature-fixture',x)
        def prefix_label(u):return h(b'src-label',x,u)
        def mask(*labels):return h(b'source-pair',x,*labels)
        L0=prefix_label(u0)
        assert len({u0,u1,u2,uf})==4
        # Attempt A. Builder constructs against one *known* future u1.
        E1=xo(sigma,mask(L0,prefix_label(u1)))
        ck(xo(E1,mask(L0,prefix_label(u1)))==sigma, 'known_witness_can_open')
        ck(xo(E1,mask(L0,prefix_label(u2)))!=sigma,'different_real_future_fails_same_capability')
        ck(xo(E1,mask(L0,prefix_label(uf)))!=sigma,'fake_future_not_same_capability')
        # Attempt B. Normalize against known baseline to enforce equality.
        Ebase=xo(sigma,mask(L0,L0))
        ck(xo(Ebase,mask(L0,L0))==sigma,'public_normalization_opens_early')
        ck(xo(Ebase,mask(L0,L0))==sigma,'legit_normalization_is_identical')
        # Attempt C. Builder chooses hidden OTS-style pair preimages.
        s0=h(b'signer-private-left',s)
        s1=h(b'signer-private-right',s)
        pub0=h(b'commit',s0);pub1=h(b'commit',s1)
        Esecret=xo(sigma,mask(s0,s1))
        ck(h(b'commit',s0)==pub0 and h(b'commit',s1)==pub1,'private_labels_commit')
        ck(xo(Esecret,mask(s0,s1))==sigma,'full_private_pair_opens')
        # The source delivers u1/u2, NOT either hidden s1. Public-only
        # rule H(u) yields a different label and does not recover sigma.
        ck(xo(Esecret,mask(s0,prefix_label(u1)))!=sigma,'real_source_lacks_private_label')
        ck(xo(Esecret,mask(s0,prefix_label(u2)))!=sigma,'second_real_source_lacks_label')
        # If builder publishes s0,s1 to remedy completeness, adversary
        # computes same pad without a witness.
        ck(xo(Esecret,mask(s0,s1))==sigma,'both_labels_published_open_early')
        # Attempt D. Use public bit labels anchored to u0, so all future
        # witnesses share the same mask. Public attacker computes both.
        b0=h(b'branch-label-zero',x,u0)
        b1=h(b'branch-label-one',x,u0)
        Ebit=xo(sigma,mask(b0,b1))
        ck(xo(Ebit,mask(b0,b1))==sigma,'bit_label_fabrication_opens_early')
        # Attempt E. Include future proof in keyed SHA mask. Different
        # future original certificates have different transcript digests.
        P1=h(b'abstract-source-certificate-A',x,u1)
        P2=h(b'abstract-source-certificate-B',x,u2)
        PF=h(b'abstract-source-certificate-fake',x,uf)
        Ecert=xo(sigma,mask(L0,h(b'certificate-label',P1)))
        ck(xo(Ecert,mask(L0,h(b'certificate-label',P1)))==sigma,
           'known_certificate_opens')
        ck(xo(Ecert,mask(L0,h(b'certificate-label',P2)))!=sigma,
           'future_certificate_misses_precommitted_key')
        ck(xo(Ecert,mask(L0,h(b'certificate-label',PF)))!=sigma,
           'fake_certificate_different')
        # Proposed source-commitment repair: bind only to the actual
        # publicly known baseline root (constant across future forks).
        C0=h(b'authenticated-baseline-root',x,u0)
        Eroot=xo(sigma,h(b'root-only',x,C0))
        ck(xo(Eroot,h(b'root-only',x,C0))==sigma,
           'baseline_only_unlocks_without_future_source')
        # No claim of authenticating source: all candidate digest bytes here
        # are synthetic, and the supposed qualifier is not in raw crypto.
    return {'run':'R214-SLB-20261110',
            'assertions':sum(counts.values()),
            'groups':dict(sorted(counts.items())),
            'scope':'toy one-sided hash label timing tests only',
            'not_implemented':['real BTC/SYS source authentication',
              'actual source-to-secret-label compiler',
              'secure Build/Open', 'native cancellation signature',
              'quantum/QROM security reduction'],
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
