#!/usr/bin/env python3
"""R258 byte-level illustrative future-anchor experiment; NOT BTC/SYS or WKEM."""
from hashlib import sha256
import json
H = lambda b: sha256(sha256(b).digest()).digest()
X = lambda a,b: bytes(x^y for x,y in zip(a,b))
xw=H(b'R258 claim/utxo, source slot, refund tx, VK, capsule binding')
sigma=H(b'R258 synthetic native cancellation signature')
# Different original-source-looking variants can share a canonical later BTC beacon,
# but that beacon is not known at setup time.
seen=set()
shared=0
same_open=0
missed=0
for t in range(1,129):
    bt=H(b'future BTC anchor'+xw+t.to_bytes(4,'big'))
    # test two different synthetic source fork records using same later anchor.
    w0=H(b'future branch 0'+bt)
    w1=H(b'future branch 1'+bt)
    assert w0 != w1
    pad=H(b'PVUGC/FUTURE-BEACON/258'+xw+bt)
    # Hypothetical ciphertext using pad succeeds only with hindsight.
    C=X(sigma,pad)
    assert X(C,H(b'PVUGC/FUTURE-BEACON/258'+xw+bt)) == sigma
    same_open += 2
    shared += 1
    # Real setup chooses a frozen guess before learning bt; also varying anchors differ.
    guess=H(b'public pre-funding guess'+xw+t.to_bytes(4,'big'))
    wrongpad=H(b'PVUGC/FUTURE-BEACON/258'+xw+guess)
    assert X(sigma,wrongpad) != C
    missed += 1
    seen.add(bt)
assert len(seen)==128
# Known-at-Build source anchor pad is public regardless of evidence or a real fork.
public=H(b'known anchor prior to funding'+xw)
public_pad=H(b'PVUGC/FUTURE-BEACON/258'+xw+public)
public_C=X(sigma,public_pad)
assert X(public_C,public_pad)==sigma
print(json.dumps({'run':'R258','distinct_synthetic_future_beacons':len(seen),
 'hypothetical_same_beacon_opens':same_open,
 'pre_setup_guess_misses':missed,
 'known_beacon_no_witness_open':1,
 'status':'nonqualifying; cannot build prior to future beacon'},sort_keys=True,indent=2))
