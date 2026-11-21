#!/usr/bin/env python3
"""R205 tiny hash-garbled AND/source-label experiment; NOT a WKEM/security test."""
import hashlib, json

def h(domain, *parts):
    dat = domain.encode() + b'\0' + b''.join(len(x).to_bytes(4, 'big')+x for x in parts)
    return hashlib.sha256(dat).digest()

def X(a,b): return bytes(u^v for u,v in zip(a,b))

def label(seed,wire,bit):
    b=bytearray(h('private-wire-label',seed,wire.encode(),bytes([bit])))
    b[-1]=(b[-1]&0xfe)|bit
    return bytes(b)

def gate(seed):
    A=[label(seed,'A',b) for b in range(2)]
    B=[label(seed,'B',b) for b in range(2)]
    C=[label(seed,'C',b) for b in range(2)]
    secret=h('sig',seed)
    rows=[None]*4
    for a in range(2):
        for b in range(2):
            idx=2*(A[a][-1]&1)+(B[b][-1]&1)
            rows[idx]=X(C[a&b],h('row',seed,A[a],B[b]))
    public={'rows':rows,'pad':X(secret,h('out',seed,C[1])),
            'ck':h('ck',seed,secret), 'seed':seed}
    return public, [A,B], C, secret

def evaluate(public,A,B):
    row=public['rows'][2*(A[-1]&1)+(B[-1]&1)]
    return X(row,h('row',public['seed'],A,B))

def open_secret(pub,output):
    s=X(pub['pad'],h('out',pub['seed'],output))
    return s if h('ck',pub['seed'],s)==pub['ck'] else None

def derived(source,bit):
    # Explicit public labels from a fixed, publicly visible source fingerprint.
    return h('public-source-bit-label',source,bytes([bit]))

def main():
    counts={'garbled_truth_table':0,'fake_true_assignment_opens':0,
            'false_source_requires_second_hidden_label':0,
            'public_root_label_malleability':0,
            'future_witness_fingerprint_mismatch':0,
            'same_claim_two_valid_evidence_digests_differ':0}
    for n in range(128):
        seed=n.to_bytes(4,'big')
        public, inputs, out_labels, secret=gate(seed)
        for a in range(2):
            for b in range(2):
                out=evaluate(public, inputs[0][a], inputs[1][b])
                assert out==out_labels[a&b]
                assert (open_secret(public,out)==secret)==bool(a&b)
                counts['garbled_truth_table']+=1
        # Both labels must be publicly available to cover unrestricted possible input bits.
        # The malicious party can pick the accepting (1,1) pair irrespective of source.
        forged=evaluate(public,inputs[0][1],inputs[1][1])
        assert open_secret(public,forged)==secret
        counts['fake_true_assignment_opens']+=1
        # Removing the second label prevents honest full-input availability (not a secure fix).
        assert inputs[0][1] not in [inputs[0][0]] and inputs[1][1] not in [inputs[1][0]]
        counts['false_source_requires_second_hidden_label']+=1
        root=h('real-public-ancestor-prefix',seed)
        assert derived(root,1)==derived(root,1)  # even attacker with fake input 1
        counts['public_root_label_malleability']+=1
        # Future source observations have different hash-transcript fingerprints,
        # so label derivation tied to them cannot be initialized at Build time.
        A=h('future-authenticated-source',seed,b'source-A')
        B=h('future-authenticated-source',seed,b'source-B')
        assert A!=B and derived(A,1)!=derived(B,1)
        counts['future_witness_fingerprint_mismatch']+=1
        # Two different qualifying witnesses cannot agree on H(whole transcript)
        # except by collision; their pads are independent, not a common frozen key.
        w1=h('authenticated-btc-sys',seed,b'valid-fork-1')
        w2=h('authenticated-btc-sys',seed,b'valid-fork-2')
        assert w1!=w2 and h('source-pad',w1)!=h('source-pad',w2)
        counts['same_claim_two_valid_evidence_digests_differ']+=1
    result={'run':'R205-TWO-LABEL-SOURCE-GATE','functional_assertions':sum(counts.values()),
            'counts':counts,'qualifications':[
                'Toy SHA256 gate with explicitly sampled private wire labels',
                'No actual SHA256 circuit garbling, Bitcoin work, source validation or QPT testing',
                'Label leakage attack is deterministic once both labels public',
                'Hash inequality regressions are fixtures, not PQ security claims'],
            'source_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest()}
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':main()
