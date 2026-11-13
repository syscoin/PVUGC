#!/usr/bin/env python3
"""R220: proof-transcript-sealed capability checks only; NO actual WKEM or ZK.

Source is an explicitly SYNTHETIC typed hash-PoW certificate, not a BTC/SYS
header, source-history proof, native signature or Bitcoin endpoint.  All
cryptographic claims are algebraic identities / classical RO calculations.
"""
from __future__ import annotations
import hashlib,json,struct
from collections import Counter

COUNTS = Counter()

def H(label: bytes, *fields: bytes) -> bytes:
    m=struct.pack('>I',len(label))+label
    m+=b''.join(struct.pack('>I',len(f))+f for f in fields)
    return hashlib.sha256(m).digest()

def xor(a,b):
    assert len(a)==len(b)
    return bytes(x^y for x,y in zip(a,b))

def check(name, assertion):
    if not assertion: raise AssertionError(name)
    COUNTS[name]+=1

def toy_work(anchor,child,nonce):
    return int.from_bytes(H(b'toy-work',anchor,child,nonce.to_bytes(4,'big'))[:2],'big') < 16

def next_work(anchor,child):
    for nonce in range(100000):
        if toy_work(anchor,child,nonce): return nonce
    raise AssertionError('toy work search exhausted')

def toy_valid(x,child,nonce):
    return len(child)==32 and child!=x['baseline'] and toy_work(x['anchor'],child,nonce)

def proof(x,child,nonce,salt):
    assert toy_valid(x,child,nonce)
    # A typed *transparent* mock proof, not ZK and not source admission.
    return b'R220-v1'+child+nonce.to_bytes(4,'big')+salt

def proof_hash(x,pi):
    return H(b'proof-transcript',x['id'],pi)

def fixed_normalizer(x,pi):
    # Same for every transcript and also for every fake transcript.
    return H(b'public-proof-normalizer',x['id'])

def source_fixture(t):
    x={'id':H(b'instance',t.to_bytes(4,'big')),
       'anchor':H(b'anchor',t.to_bytes(4,'big')),
       'baseline':H(b'baseline',t.to_bytes(4,'big'))}
    c0=H(b'child-A',t.to_bytes(4,'big'))
    c1=H(b'child-B',t.to_bytes(4,'big'))
    n0=next_work(x['anchor'],c0)
    n1=next_work(x['anchor'],c1)
    return x,(c0,n0),(c1,n1)

def run():
    two_different=0
    for t in range(32):
        x,(a,na),(b,nb)=source_fixture(t)
        check('distinct_synthetic_qualifying_inputs',a!=b and toy_valid(x,a,na) and toy_valid(x,b,nb))
        ra=H(b'first-salt',x['id'])[:16]
        rb=H(b'second-salt',x['id'])[:16]
        pa=proof(x,a,na,ra)
        pb=proof(x,b,nb,rb)
        pa2=proof(x,a,na,rb)
        check('different_valid_proofs_different_bytes',pa!=pb)
        check('same_valid_witness_distinct_prover_randomness',pa!=pa2)
        K=proof_hash(x,pa)
        sigma=H(b'pretend-native-cancel',x['id'])
        D=xor(sigma,K)
        check('designated_proof_opens',xor(D,proof_hash(x,pa))==sigma)
        check('another_valid_proof_does_not_open_same_signature',xor(D,proof_hash(x,pb))!=sigma)
        check('same_witness_different_prover_nonce_fails',xor(D,proof_hash(x,pa2))!=sigma)
        two_different+=1
        # Normalizing to x makes every proof share one hash -- with no witness.
        public_pad=fixed_normalizer(x,pa)
        D2=xor(sigma,public_pad)
        check('honest_normalized_proof_opens',xor(D2,fixed_normalizer(x,pb))==sigma)
        fake=b'unauthenticated-fabrication-with-no-work'
        check('fake_source_public_normalizer_opens',xor(D2,fixed_normalizer(x,fake))==sigma)
        # Even if an honest opener rejects this child/nonce, the raw pad is public.
        bad_child=H(b'fake-child',x['id'])
        bad_nonce=next(i for i in range(16) if not toy_work(x['anchor'],bad_child,i))
        check('fake_source_rejected_by_honest_verifier',not toy_valid(x,bad_child,bad_nonce))
    # A target-seeking Fiat-Shamir proof salt is a PREIMAGE grind against a
    # frozen target; q independent classical RO probes succeed with
    # probability 1-(1-2^-lambda)^q.  This is an analytical bound, not an
    # experiment proving QROM bounds or independent SHA outputs.
    trials=[]
    for j in range(20):
        x,(a,na),_=source_fixture(80+j)
        target=int.from_bytes(H(b'target',x['id'])[:2],'big') >> 4
        found=None
        for r in range(4096):
            pi=proof(x,a,na,r.to_bytes(4,'big'))
            candidate=int.from_bytes(proof_hash(x,pi)[:2],'big') >> 4
            if candidate==target:
                found=r+1
                break
        trials.append(found)
        check('fixed_target_grind_classically_costly_or_unfound',found is None or found>=1)
    p=1-(1-2**-12)**4096
    empirical=sum(v is not None for v in trials)/len(trials)
    # Calibration only.  No fixed upper/lower assertion about random samples.
    result={
      'run':'R220_FS_SOURCE_GATE_20261111',
      'assertions':sum(COUNTS.values()),
      'groups':dict(sorted(COUNTS.items())),
      'distinct_source_pairs':two_different,
      'grind_bits':12,'max_classical_queries_per_trial':4096,
      'grind_trials':len(trials),
      'grind_success_count':sum(v is not None for v in trials),
      'grind_expected_success_probability_in_RO':round(p,6),
      'grind_empirical_success_fraction':empirical,
      'grind_first_success_queries':trials,
      'claims': 'functional transcript nonconvergence + public normalizer leak; random-oracle target search is only a classical bound',
      'NOT_IMPLEMENTED':['original BTC/SYS source','actual ZK','QPT proof','native signatures','cryptographic conditional release'],
    }
    return result

if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
