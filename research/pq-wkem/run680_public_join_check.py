#!/usr/bin/env python3
"""Run 680 finite, exact counterexample to 'encrypt+public join+public open'.
This is a 4-bit ONE-TIME PAD illustration; it does NOT implement PKE, FHE, FE or WKEM.
All counts are exact exhaustive combinatorics; no cryptographic security claims.
"""
import collections
import hashlib
import json

WIDTH=4
N=1<<WIDTH
VALID_WITNESSES=(3,7,11,15)


def public_join(c_secret,c_witness,witness,rand):
    """Arbitrary illustrative nonlinear public postprocessing of both ciphertexts."""
    a=(c_secret + 3*c_witness + rand*5) % N
    b=((c_secret << 1) | (c_secret >> (WIDTH - 1))) & (N-1)
    digest=hashlib.sha256(bytes((a ^ b, c_witness ^ witness,rand))).digest()
    return (a ^ b,digest[0]&15,digest[1]&15)


def main():
    assertions=0
    results={}
    for w in VALID_WITNESSES:
        assert (w & 3)==3
        assertions+=1
        by_key={}
        for key in range(N):
            counter=collections.Counter()
            # pad_0 and pad_w independent, public mix randomness independent
            for pad0 in range(N):
                for padw in range(N):
                    for rand in range(4):
                        c0=key ^ pad0
                        cw=w ^ padw
                        output=public_join(c0,cw,w,rand)
                        counter[output]+=1
            assert sum(counter.values()) == N*N*4
            assertions+=1
            by_key[key]=counter
        assert all(by_key[k] == by_key[0] for k in range(1,N))
        assertions+=N-1
        # Every transcript has uniform posterior over the 16 possible keys.
        # Optimal public key guess given only the public output has success 1/16.
        posterior=collections.defaultdict(lambda:collections.Counter())
        for k,count in by_key.items():
            for event,multiplicity in count.items():
                posterior[event][k]=multiplicity
        optimal_success=sum(max(v.values()) for v in posterior.values())
        total=sum(sum(v.values()) for v in posterior.values())
        assert optimal_success*N==total
        assertions+=1
        results[str(w)]={
            "keys":N,
            "public_output_support":len(by_key[0]),
            "raw_enumerated_transcripts_per_key":N*N*4,
            "optimal_public_recovery":"1/16",
            "identical_distributions_for_all_16_keys":True,
        }

    # Public auxiliary information correlated with the key alters the game.
    # Deliberately toy 'verification tag' = key mod 4. This is NOT an actual
    # public signature verification key (would be insecure at toy scale).
    aux_success=0
    aux_total=0
    for key in range(N):
        for pad in range(N):
            c0=key^pad
            tag=key&3
            candidates=[k for k in range(N) if (k&3)==tag]
            # For each pair (ciphertext,tag), posterior is uniform over 4 keys.
            assert len(candidates)==4
            assertions+=1
            aux_total+=1
            if key == min(candidates):
                aux_success+=1
    assert aux_success*4==aux_total
    assertions+=1

    # Two independently padded capsules for the SAME key also leak nothing.
    pair_by_key={}
    for key in range(N):
        pairs=collections.Counter((key ^ p1, key ^ p2)
                                  for p1 in range(N) for p2 in range(N))
        pair_by_key[key]=pairs
        assert len(pairs)==N*N and set(pairs.values())=={1}
        assertions+=1
    assert all(pair_by_key[k] == pair_by_key[0] for k in range(1,N))
    assertions+=N-1

    print(json.dumps({
        "run":680,
        "fixture":"exact 4-bit OTP; public late-witness encryption; public nonlinear join",
        "relation":"(w & 3) == 3",
        "valid_original_witnesses":list(VALID_WITNESSES),
        "per_witness_statistics":results,
        "correlated_public_tag":"K mod 4 (toy ONLY)",
        "optimal_guess_with_tag":"1/4",
        "optimal_guess_without_tag":"1/16",
        "two_independently_padded_capsules_leak_no_key_information":True,
        "assertions":assertions,
        "scope":"finite information-theoretic sanity check, not a proof of PKE IND-CPA or WKEM"
    },indent=2,sort_keys=True))


if __name__=="__main__":
    main()
