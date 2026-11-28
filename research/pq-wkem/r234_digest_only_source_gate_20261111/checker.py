#!/usr/bin/env python3
"""Exact factorization / preseal tests for digest-only source-branch carriers.
This is NOT authenticated SHA/AuxPoW, a KEM, or a security proof.
"""
import hashlib, json

def h(tag,*parts):
    out=tag.encode()+b'\0'
    for part in parts: out+=len(part).to_bytes(4,'big')+part
    return hashlib.sha256(out).digest()

def xor(x,y): return bytes(a^b for a,b in zip(x,y))
def bit(v,i): return (v>>(7-i))&1

def firstdiff(a,b):
    for i in range(8):
        if bit(a,i)!=bit(b,i): return i
    return None

def report():
    # Equal result across ALL synthetic semantic contradictions is possible
    # with polynomially many public rows, but no authenticated label transfer.
    baseline=0xA5
    sigma=h('native-sig-fixture',b'bound-claim')
    # The public anchor supplies every opposite input label; real work is absent.
    rows=[]
    for i in range(8):
        wanted=1-bit(baseline,i)
        label=h('public-label',bytes([baseline,i,wanted]))
        rows.append(xor(sigma,h('pad',label)))
    correct=0
    forged=0
    seen=set()
    for other in range(256):
        if other==baseline: continue
        i=firstdiff(baseline,other)
        other_label=h('public-label',bytes([baseline,i,bit(other,i)]))
        got=xor(rows[i],h('pad',other_label))
        assert got==sigma
        correct+=1; seen.add(i)
        # An unqualified assertion of that SAME semantic value provides
        # identical labels: exact byte-for-byte early release.
        fake_other=other
        j=firstdiff(baseline,fake_other)
        recovered=xor(rows[j],h('pad',h('public-label',bytes([baseline,j,bit(fake_other,j)]))))
        assert recovered==sigma
        forged+=1
    assert seen==set(range(8))
    # Repair attempt A: secret setup labels; the honest public evaluator lacks
    # the preimage that the actual SHA/AuxPoW evidence does NOT include.
    setup_secret=h('private-seed',b'example')
    secret_labels=[h('private-label',setup_secret,bytes([baseline,i,1-bit(baseline,i)])) for i in range(8)]
    private_rows=[xor(sigma,h('pad',s)) for s in secret_labels]
    public_guess=xor(private_rows[0],h('pad',h('public-label',bytes([baseline,0,1-bit(baseline,0)]))))
    assert public_guess!=sigma
    # Repair attempt B: choose rows keyed by one future certificate. Different
    # valid alternative certificates with identical *semantic* discrepancy do
    # not share the new transcript-derived pad; frozen rows do not converge.
    work1=h('synthetic-workid',b'parent-work-one')
    work2=h('synthetic-workid',b'parent-work-two')
    i=firstdiff(baseline,baseline^0x80)
    row=xor(sigma,h('transcript-pad',work1,bytes([i])))
    assert xor(row,h('transcript-pad',work1,bytes([i])))==sigma
    assert xor(row,h('transcript-pad',work2,bytes([i])))!=sigma
    # Different parent-work certificates for SAME child/outcome do not change
    # the semantic mismatch predicate; the certificate is for authenticity.
    same_child_semantic=baseline
    assert firstdiff(baseline,same_child_semantic) is None
    # A source-free, prefix-only gate exposes the mask from a syntactic prefix.
    work_prefix=b'\0'*3
    sealed=xor(sigma,h('work-prefix-pad',work_prefix))
    assert xor(sealed,h('work-prefix-pad',b'\0'*3))==sigma
    return {'candidate':'R234-digest-factorization','functional_checks':correct+forged+6,
      'all_semantic_conflicts_return_same':correct,
      'fake_semantic_conflicts_return_same':forged,
      'covered_first_differing_indices':sorted(seen),
      'private_label_public_derivation_failed':True,
      'work_dependent_pad_other_certificate_fails':True,
      'known_prefix_alone_opens':True,
      'not_tested':['actual BTC or SYS source authentication','native PQ verification','QPT or QROM'],
      'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}

if __name__=='__main__': print(json.dumps(report(),sort_keys=True,indent=2))
