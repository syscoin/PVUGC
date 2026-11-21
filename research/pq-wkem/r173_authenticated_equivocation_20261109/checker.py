#!/usr/bin/env python3
"""R173 restricted hash-equivocation carrier; NOT an ORIGINAL NP WKEM."""
import hashlib, json

def H(tag,*a):
    d=tag.encode()+b'\0'+b''.join(len(z).to_bytes(4,'big')+z for z in a)
    return hashlib.sha256(d).digest()
def xor(a,b):return bytes(x^y for x,y in zip(a,b))
def bit(x,i):return (x>>(7-i))&1

def build(seed,n=3):
    parts=[];K=bytes(32)
    for j in range(n):
        s=H('share',seed,bytes([j]));K=xor(K,s)
        pairs=[(H('zero',seed,bytes([j,i])),H('one',seed,bytes([j,i]))) for i in range(8)]
        pub=[(H('verify',a),H('verify',b)) for a,b in pairs]
        rows=[xor(s,H('pair',bytes([j,i]),a,b)) for i,(a,b) in enumerate(pairs)]
        parts.append((pairs,pub,rows))
    sig=H('frozen-native-signature',seed)
    capsule={'vks':[x[1] for x in parts], 'rows':[x[2] for x in parts],
             'check':H('check',K), 'sealed':xor(sig,H('pad',K))}
    return capsule,[x[0] for x in parts],K,sig

def sign(pairs,outcome):return [pairs[i][bit(outcome,i)] for i in range(8)]

def open_share(c,j,a,sa,b,sb):
    if a==b or sa is None or sb is None:return None
    for i in range(8):
        if H('verify',sa[i])!=c['vks'][j][i][bit(a,i)]:return None
        if H('verify',sb[i])!=c['vks'][j][i][bit(b,i)]:return None
    for i in range(8):
        if bit(a,i)==bit(b,i):continue
        x,y=(sa[i],sb[i]) if bit(a,i)==0 else (sb[i],sa[i])
        return xor(c['rows'][j][i],H('pair',bytes([j,i]),x,y))
    return None

def open_all(c,shares):
    if any(s is None for s in shares):return None
    K=bytes(32)
    for s in shares:K=xor(K,s)
    return xor(c['sealed'],H('pad',K)) if H('check',K)==c['check'] else None

def run():
    results={'valid_conflicts_open':0,'same_outcome_work_variants_not_forks':0,
             'forged_second_opening_rejected':0,'malicious_source_retention_opens_early':0,
             'one_honest_single-signature_stops_early_release_but_blocks_liveness':0,
             'prepublished_honest_second_opening_releases_early':0}
    for t in range(60):
        c,parts,K,sig=build(t.to_bytes(4,'big'))
        a=(7*t)%256
        for h in range(8):
            b=a^(1<<h)
            sa=[sign(p,a) for p in parts];sb=[sign(p,b) for p in parts]
            shares=[open_share(c,j,a,sa[j],b,sb[j]) for j in range(3)]
            assert open_all(c,shares)==sig;results['valid_conflicts_open']+=1
        assert open_share(c,0,a,sa[0],a,sa[0]) is None
        results['same_outcome_work_variants_not_forks']+=1
        assert open_share(c,0,a,sa[0],b,sa[0]) is None
        results['forged_second_opening_rejected']+=1
        # If all source signers are malicious and retain both labels,
        # they reconstruct the FULL key and signature before any source event.
        early_shares=[]
        for j in range(3):
            x,y=parts[j][0]
            early_shares.append(xor(c['rows'][j][0],H('pair',bytes([j,0]),x,y)))
        assert open_all(c,early_shares)==sig
        results['malicious_source_retention_opens_early']+=1
        # One honest share withheld: corrupted cosigners cannot reconstruct K.
        assert open_all(c,shares[:2]+[None]) is None
        results['one_honest_single-signature_stops_early_release_but_blocks_liveness']+=1
        # If both openings from honest signer are publicly available before event,
        # the entire key and frozen capability are already recoverable.
        assert open_all(c,shares)==sig
        results['prepublished_honest_second_opening_releases_early']+=1
    results['assertions']=sum(results.values())
    results['status']='restricted pair-opening correctness; early retention and online-authority failure; no ORIGINAL NP release'
    return results

if __name__=='__main__':print(json.dumps(run(),sort_keys=True,indent=2))
