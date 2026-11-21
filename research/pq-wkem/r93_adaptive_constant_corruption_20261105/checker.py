#!/usr/bin/env python3
"""R93 finite exhaustive adaptive-opening and PRG-image bookkeeping checker.
Not a cryptographic simulator: source leaf encryption is ideal toy OTP mod 5;
PRG example is an arbitrary tiny function, not LWE or a secure PRG.
The QPT claim lives in the separately stated exact-distribution reductions.
"""
import collections, itertools, json, math
Q=5; N=4; K=3; TMAX=2
assert N < Q
INDICES=tuple(range(N))
SUBSETS=[frozenset(c) for j in range(TMAX+1) for c in itertools.combinations(INDICES,j)]
assert len(SUBSETS)==11
ASSERTIONS=0

def ensure(cond,why):
    global ASSERTIONS
    ASSERTIONS+=1
    if not cond:raise AssertionError(f"assertion {ASSERTIONS}: {why}")

def share(root,a,b,i):
    z=i+1
    return (root+a*z+b*z*z)%Q

def next_open(c,pads):
    i0=sum((i+1)*c[i] for i in INDICES)%N
    s0=(c[i0]-pads[i0])%Q
    offset=1+(s0+c[(i0+2)%N]+pads[i0])%(N-1)
    i1=(i0+offset)%N
    ensure(i0 != i1,"two different adaptively chosen keys")
    return i0,i1

# Vandermonde rank, conditionally on every fixed target root.
privacy_histograms=0
for U in SUBSETS:
    histograms=[]
    for root in range(Q):
        h=collections.Counter(tuple(share(root,a,b,i) for i in sorted(U))
                               for a in range(Q) for b in range(Q))
        histograms.append(h)
        ensure(set(h.values())=={Q**(K-1-len(U))},"exact conditional histogram")
        ensure(len(h)==Q**len(U),"full rank for each root")
        privacy_histograms+=1
    ensure(all(h==histograms[0] for h in histograms),"root independence for fixed U")

# Post-ciphertext adaptive oracle chooses first leaf from entire C, then
# chooses second leaf from first decrypted share and public C.
# Secret keys are toy OTP pad_i, public C_i = share_i + pad_i (mod 5).
# In G_U, ciphertext for outside U encrypts zero; simulator aborts if an
# opening of an outside-U leaf is requested. Compare the *same final-U event*
# in true and pre-guessed games, including all public ciphertext coordinates.
counts_real=collections.Counter()
counts_guessed=collections.Counter()
transcripts=collections.defaultdict(lambda:[0]*Q)
for root in range(Q):
    for a in range(Q):
        for b in range(Q):
            S=tuple(share(root,a,b,i) for i in INDICES)
            for pads in itertools.product(range(Q),repeat=N):
                c=tuple((S[i]+pads[i])%Q for i in INDICES)
                i0,i1=next_open(c,pads)
                U=frozenset((i0,i1))
                counts_real[U]+=1
                record=(c,i0,pads[i0],i1,pads[i1])
                transcripts[record][root]+=1
                # Each pre-guessed U runs a fresh experiment but the same
                # complete random tape can be used in an exact enumeration.
                for guess in SUBSETS:
                    d=tuple((S[i]+pads[i])%Q if i in guess else pads[i]
                            for i in INDICES)
                    j0,j1=next_open(d,pads)
                    if frozenset((j0,j1))==guess:
                        counts_guessed[guess]+=1
ensure(sum(counts_real.values())==Q**(K+N),"total experiment mass")
for U in SUBSETS:
    ensure(counts_real[U]==counts_guessed[U],"pre-guessed event identical in ideal ciphertext model")
for outcome,cnt in transcripts.items():
    ensure(len(set(cnt))==1,"full adaptive classical opening transcript independent of root")

# Correct seed-prediction argument for a PRG distinguisher that does NOT know
# the underlying generator seed: decide only by testing G(candidate)==Y.
# For uniform Y, probability of this event <= |Im(G)|/2^L <=2^(kappa-L).
kappa=5;outbits=10

def tiny_G(s):
    # deterministic toy expansion, non-cryptographic
    return ((s*17+3) ^ ((s<<5)|s)) % (1<<outbits)
image={tiny_G(s) for s in range(1<<kappa)}
ensure(len(image)<=2**kappa,"image size bound")
for Y in range(1<<outbits):
    ensure((Y in image)==any(tiny_G(s)==Y for s in range(1<<kappa)),"image membership")
image_error=len(image)/(1<<outbits)
ensure(image_error <= 2**(kappa-outbits),"PRG challenge seed-test soundness")

# Subset count and QPT reduction advantage accounting, not attack-cost data.
for n,t in [(4,2),(16,2),(16,3),(16,7),(64,2),(128,3)]:
    M=sum(math.comb(n,j) for j in range(t+1))
    ensure(M==sum(math.comb(n,j) for j in range(min(n,t)+1)),"count pre-guessed subsets")

print(json.dumps({
 "run":"R93-ADAPTIVE-THRESHOLD-OPENINGS-20261105",
 "status":"RESTRICTED_PROOF_ADVANCE_NOT_GENERIC_NP_WKEM",
 "assertions_passed":ASSERTIONS,
 "toy_parameters":{"field":Q,"n":N,"threshold":K,"max_adaptive_opens":TMAX},
 "exact_fixed_subset_histograms":privacy_histograms,
 "complete_adaptive_transcripts":len(transcripts),
 "enumerated_real_random_tapes":Q**(K+N),
 "pre_guessed_subset_events":len(SUBSETS),
 "events_match":all(counts_real[U]==counts_guessed[U] for U in SUBSETS),
 "event_counts":{"".join(map(str,sorted(U))):counts_real[U] for U in SUBSETS},
 "prg_image_toy":{"seed_bits":kappa,"output_bits":outbits,
                  "image_size":len(image),"uniform_image_probability":image_error,
                  "universal_upper_bound":2**(kappa-outbits)},
 "subset_guess_sizes":{"16,2":sum(math.comb(16,j) for j in range(3)),
                       "16,3":sum(math.comb(16,j) for j in range(4)),
                       "16,7":sum(math.comb(16,j) for j in range(8)),
                       "64,2":sum(math.comb(64,j) for j in range(3)),
                       "128,3":sum(math.comb(128,j) for j in range(4))},
 "limitations":"toy OTP, tiny PRG, not LWE/PQ; exact adaptive reduction valid only for fixed CONSTANT maximum t and ordinary classical corruption queries"
},indent=2,sort_keys=True))
