#!/usr/bin/env python3
"""Exhaustive finite-oracle distribution identity; not a source/FE implementation."""
from fractions import Fraction
from itertools import product
import json


def exact(b=8, targets=(0,1,2), horizon=4):
    # Enumerate every length-horizon table of random oracle outputs, each equally likely.
    accepted = set(targets)
    histogram = {t: 0 for t in targets}
    no_success = 0
    for transcript in product(range(b), repeat=horizon):
        witness = next((t for t in transcript if t in accepted), None)
        if witness is None:
            no_success += 1
        else:
            histogram[witness] += 1
    total = b**horizon
    success = total-no_success
    assert success > 0 and success % len(targets) == 0
    assert len(set(histogram.values())) == 1, histogram
    exact_probability = [str(Fraction(histogram[t],success)) for t in targets]
    assert all(Fraction(histogram[t],success)==Fraction(1,len(targets)) for t in targets)
    assert Fraction(no_success,total) == (Fraction(b-len(targets),b)**horizon)
    # A digest-only decoder is any arbitrary deterministic map f(t) whose outputs
    # can include the frozen secret S. Its real and forged success probabilities
    # are identical, because its input distribution is identical.
    for success_mask in product((False,True), repeat=len(targets)):
        real = sum((Fraction(histogram[t],success) for i,t in enumerate(targets) if success_mask[i]), Fraction(0))
        fake = Fraction(sum(success_mask),len(targets))
        assert real == fake, (real,fake)
    return {"oracle_outputs": b, "accepted_values": list(targets),
            "candidate_limit": horizon, "enumerated_oracles": total,
            "conditioned_digest_distribution": exact_probability,
            "no_valid_header_probability": str(Fraction(no_success,total)),
            "all_digest_only_success_functions_matched": 2**len(targets)}

if __name__ == "__main__":
    print(json.dumps({"scope":"exhaustive ideal random-oracle enumeration; no AuxPoW, native signing, QPT or FE", 
                      "cases":[exact(horizon=h) for h in (1,2,3,4,5)]},sort_keys=True,indent=2))
