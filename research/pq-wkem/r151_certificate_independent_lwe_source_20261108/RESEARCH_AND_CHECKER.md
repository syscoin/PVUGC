# R151 — ORIGINAL-witness proof gate on independent LWE ciphertext

**STATUS: REJECTED source component; no positive advance toward generic NP witness-KEM, no user notification milestone.** Bounded offline theorem-and-checker iteration; no efficiency work or external internet/literature.

**Continuity:** syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, starting head aa2b32eea18d8fc9e558315187480c31e46d952a. The exact R150 (RESEARCH.md blob 1c747a7984339bc001e11a151fcb2f3d54875476) and R149 (blob a898438d6b223c5bcdd60acaa696a1f0703116a9) were read. Latest substantive ordinary PR comment checkpoint 6698876958. No new ordinary PR comment was proposed because this is not a qualifying constructive result.

## Candidate and FULL joint distribution

Compile the generic ORIGINAL NP verifier R(x,w), binding the claim/UTXO, branch, anchors/windows, source relation identity, context, challenge path, and intended native VK. Fix an ordinary QPT IND-CPA LWE PKE. Classical-PPT Build draws (pk,sk), chooses a capability seed K in a prescribed seed space, publishes ciphertext c=Enc_pk(K;rho), and publishes a proof-checking CRS, CK/J/Aux, contextual public fields and related capsules. **In this tested subfamily**, conditioned on (pk,x), the entire latter joint distribution is samplable from independent coins without sk, K or rho. Valid ORIGINAL w permits a public certificate pi=Prove(CRS,R,x,w) with Check(CK,x,pi)=1. Open uses any classical-PPT computation on (full View,w,pi), not a SourceOpen oracle, and is required to recover the SAME K from every valid ORIGINAL witness (distinct witnesses need not share trace).

This is a bona fide attempt to insert the ORIGINAL witness into a real public source-opening interface rather than rely on special issued LWE credentials. It is **not** a working scheme: a public proof that merely authorizes a computation cannot supply the missing decryption correlation.

## Exact easy-TRUE impossibility for this subfamily

Take any easy YES statement x0 with publicly computable valid witness w0. Suppose a claimed Open recovers each one of two equal-length capability seed messages k0 != k1 with errors eps0, eps1 respectively. Construct a straight-line ordinary QPT IND-CPA adversary B:

1. Give the LWE challenger messages k0,k1 and receive (pk,c*) encrypting kb.
2. Set x=x0, calculate w0, generate actual public proof pi, and sample the *entire* CK/J/Aux/context/related-capsule joint distribution using the specified secret-independent simulator with (pk,c*) substituted. The simulator must preserve every checking-key correlation; neither sk nor challenge encryption randomness nor an unknown K is available.
3. Run the real Open once on the complete simulated public view and known ORIGINAL witness w0; output b'=1 exactly when its output equals k1.

For b=0, Pr[B=1]≤eps0. For b=1, Pr[B=1]≥1-eps1. Therefore the conditional probability gap is at least 1-eps0-eps1, and the distinguishing advantage above 1/2 is at least (1-eps0-eps1)/2. This contradicts QPT IND-CPA whenever the correctness errors are negligible. The reduction is straight-line and valid with arbitrary independent nonuniform QPT advice, without quantum rewinding. The argument permits full joint related capsules only when their sampling is correctly simulated from independent coins. It is enough to refute the candidate on an easy-TRUE relation; no arbitrary witness extractor is requested.

It is NOT an impossibility theorem for source-dependent encryption, generic WE, correlated checking keys, or native-signature-specific capability distributions. The native signing VK can itself depend on the signature K; the above two-challenge argument applies directly only to a capability seed with an independently simulatable checking distribution, not to an unmodeled CK containing secret-dependent VK. If CK contains hidden K/sk-dependent information, the simulator does not exist and this reduction cannot be invoked.

## Repair investigated and exact remaining source equation

One could publish Help(R,x,sk,K,rho) so that a valid ORIGINAL witness's publicly generated pi helps Open recover K. But if Help is independently jointly simulatable from pk,x, the above IND-CPA reduction survives unchanged. If Help depends on the LWE challenge secret or correlated CK, the reduction cannot sample the full challenge view: this is the exact **source-dependent compiler** and full-public correlation that must be independently instantiated and proven. Calling Help a proof, encrypted gate, authorization token, NIZK CRS or witness-driven oracle does not construct it.

The next non-duplicative candidate must specify classical-PPT Comp(R,x) and real source-dependent Help/Open with genuine LWE keys and challenge simulator, such that Open(View,w)=SAME K for ALL original R(x,w)=1; unauthorized arbitrary-QPT K recovery/native forgery yields an actual ORIGINAL witness or independently justified QPT break without an adversary-supplied representation. A source relying only on a public affine projector inherits R138/R149 rational attacks and R150 ideal-functional extraction. FALSE-instance full-public security, hard-TRUE extraction, malicious N-of-N setup/abort, DA, SYS/BTC source assumptions and native PQ endpoint remain unresolved.

## Exact executed bounded offline checker

The following CPython 3 standard-library code was executed as checker.py. Its output was captured in captured.json, below. It exhaustively checks a toy **independent perfect pad**, illustrating the exact source-independence premise; it is NOT an LWE or QPT security test. Different toy witnesses 3 and 12 both satisfy the chosen easy-TRUE relation.

~~~python
#!/usr/bin/env python3
"""R151 finite perfect-pad witness-independent-source sanity checker.
This tests exact distribution identities, NOT LWE or QPT hardness.
"""
from collections import Counter
import itertools, json, hashlib
n=4
valid=(3,12)
checks=0
records=[]
for w in valid:
    for k in range(1<<n):
        hist=Counter(k ^ r for r in range(1<<n))
        assert len(hist)==1<<n
        assert all(hist[c]==1 for c in range(1<<n));checks+=1
        records.append((w,k,tuple(hist[c] for c in range(1<<n))))
# For uniform K and independent R, conditioning on any (C,w) keeps K uniform.
for w in valid:
    for c in range(1<<n):
        posterior=Counter()
        for k in range(1<<n):
            for r in range(1<<n):
                if (k^r)==c: posterior[k]+=1
        assert len(posterior)==1<<n
        assert set(posterior.values())=={1}; checks+=1
# On every exact public view with uniform K, best deterministic estimator has 1/16 success.
for w in valid:
    for c in range(1<<n):
        correct=0
        arbitrary_guess=c
        for k in range(1<<n):
            for r in range(1<<n):
                if k^r==c and arbitrary_guess==k:correct+=1
        assert correct==1;checks+=1
output={"candidate":"R151 source-independent proof gate", "n":n,"valid_witnesses":list(valid),"assertions":checks,"posterior_max_probability":"1/16","conclusion":"witness-independent perfect pad reveals no capability even for known valid witness; not a QPT hardness test"}
print(json.dumps(output,sort_keys=True,indent=2))
~~~

~~~json
{
  "assertions": 96,
  "candidate": "R151 source-independent proof gate",
  "conclusion": "witness-independent perfect pad reveals no capability even for known valid witness; not a QPT hardness test",
  "n": 4,
  "posterior_max_probability": "1/16",
  "valid_witnesses": [3, 12]
}
~~~

Actual local checker.py SHA-256: aa3767c65ec42637ca08d38bc26944ddb6e51aa324e8db395d847bbbea299db7. Actual captured.json SHA-256: 839f8d36226aa36f6c502fa4e3986ed425ddfd8d242e72dd2638fe2529b16604. No independent agent was invoked. No production, workflow, merge or native deployment change.
