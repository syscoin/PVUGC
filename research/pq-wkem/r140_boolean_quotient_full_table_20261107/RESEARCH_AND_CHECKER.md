# R140 — full Boolean-quotient masking, an exact but non-PPT control

**Run:** R140-BOOLEAN-QUOTIENT-FULL-TABLE-20261107. **Status: NOT a constructive advance toward a practical generic witness-KEM.** This tests a truly global Boolean-consistency source instead of R139's degree-three pseudo-moments. No optimization or internet/literature research.

## Provenance

Repository syscoin/PVUGC draft PR #1, branch research/pq-wkem-validation-20260918, starting head 183ea4b82d7de49e4da2e2d58d1f01dd0072d781. Exact R139 predecessor: research/pq-wkem/r139_k4_cubic_pseudomoment_20261107/RESEARCH_AND_CHECKER.md, Git blob efc444085d55f21bebb8262e011588191f0da100. That proposed source fails because globally inconsistent K4 parity constraints admit a degree-three fractional pseudomoment pseudo-opening. This run builds an explicit full-Boolean-point analogue, proves its ideal properties, and identifies why it is not yet polynomial-time.

## Original-dependent release algorithm (exponential reference, not cryptographic deployment)

Let R(x,w) be any NP relation with a Boolean witness w in {0,1}^n, and let C_1(x,w),...,C_m(x,w) in F_q be polynomial-time-computable constraints whose simultaneous zero condition is EXACTLY R(x,w)=1. Here x includes ORIGINAL relation identity, actual claim/UTXO, branch, anchors/window, native path, intended verification key and context. Use the Boolean quotient B_n=F_q[z_1,...,z_n]/(z_i^2-z_i), represented explicitly by its evaluation table on all 2^n Boolean points. A ring map B_n -> F_q is necessarily evaluation at a Boolean point: every generator's image is idempotent and a field has only idempotents 0,1.

For a fixed scalar capability k in F_q, honest Build samples independent private uniform A_j(a) in F_q for every j and every Boolean assignment a. Publish only the table

    P(a) = k + sum_j C_j(x,a)*A_j(a) mod q.

Do NOT publish A_j, their seeds, their raw polynomial circuits, or an additional unmasked description of k. Honest Open given *the ORIGINAL w* checks R(x,w)=1 off chain, then returns P(w). All valid witnesses return exactly the SAME precommitted k regardless of their witness states, on EVERY tape. This is an actual release rule, not a hidden SourceOpen oracle. For long native signatures, run independent field-coordinate masking; local native presigning, public VK and claim/graph binding remain separate required pieces, not claims proved here.

### Full-public fixed-FALSE theorem (information-theoretic, not LWE)

When R(x,.) is FALSE, at each Boolean a there exists some index j(a) with C_j(a) nonzero. Condition on all random A_j(b) except A_{j(a)}(a). The single remaining uniform field variable makes P(a) uniform independent of k. Different assignments use independent private coordinates, hence *the complete public table P* is independent uniform F_q^(2^n), for every k. This is exact for any distinguisher, even unbounded/quantum, provided all J/CK/Aux are deterministic functions of actual public P and independent public coins, and no private mask, hidden seed, secret signature receipt or related-capsule correlation is disclosed. If native VK is correlated with the frozen signature, source table independence still holds conditionally on that fixed signature/VK but native unforgeability would need a separate argument. A related capsule must use independently sampled masks and a separate appropriate signature/capability unless a complete selective-opening analysis justifies reuse. No such real-world composition proof is supplied.

This defeats R139's *particular* public fractional-pseudomoment opening: there is no ring homomorphism B_n -> F_q evaluating non-Boolean pseudomoments. The entire Boolean quotient is used, not a truncated 42-dimensional local moment system. This does NOT imply a polynomial-size encoding of its full-public law.

### Why it fails the user's requirement

The table is 2^n field elements, and both classical Build and public distribution take exponential resources. Its naive per-assignment storage for one 7856-byte frozen native signature is 7856*2^n bytes: 502784 at n=6; 8237613056 at n=20; 33741263077376 at n=32. This violates classical-PPT practicality and generic-NP security parameterization. A succinct *public circuit* literally describing k + sum C_j A_j reveals k and the masks; simply replacing a table by a public seeded formula is not hiding. A proof that the full table is statistically hiding for FALSE does not supply a polynomial-size cryptographic encoding or an arbitrary hard-TRUE QPT recovery-to-ORIGINAL-witness reduction. We instantiate NO statement-dependent standard-QPT-LWE source/challenge simulator and NO actual joint correlation for native signatures, N-of-N ceremony, selective openings or auxiliary receipts.

This is a bounded **control**, not a surviving construction or an efficiency result. It should not be reported to the user as progress. The indispensable next equation is a polynomial-time, polynomial-size \`Enc(x,k;rho)\` / \`Open(Enc,w)=k\` whose real public law includes all source-dependent checking keys, native VK, claim context, auxiliary and sibling capsules and is QPT hiding for FALSE; every valid ORIGINAL witness returns the identical bound k; every arbitrary unauthorized hard-TRUE recovery/native forgery yields an actual ORIGINAL witness or independently justified PQ break. A release simulator must generate all source/key/opening correlations without challenge secrets, never assume SourceOpen or adversary-supplied internal representation.

## K4 finite checker

The six Boolean edge variables of K4 satisfy one parity equation at each vertex. For b=(1,0,0,0), XORing all four equations gives 0=1, a FALSE ORIGINAL input. For b=(0,0,0,0), exactly eight valid assignments exist. Each C_v is the Boolean indicator that the parity equation at vertex v is violated (equivalent on Boolean points to the corresponding four forbidding 3-CNF clauses). q=7. The exact executable Python 3 standard-library checker below verifies per-point conditional uniformity by enumerating the field masks, checks every valid TRUE witness returns the common k across 48 independently sampled tables, verifies all Boolean points fail the charged instance, and checks idempotents and exponential resource accounting. It checks finite functionality, NOT QPT hardness.

~~~python
#!/usr/bin/env python3
import hashlib, itertools, json, random
Q=7
EDGES=tuple(itertools.combinations(range(4),2))
STARS=tuple(tuple(i for i,(a,b) in enumerate(EDGES) if a==v or b==v) for v in range(4))
NUM=1<<len(EDGES)
FALSE_B=(1,0,0,0)
TRUE_B=(0,0,0,0)
RNG=random.Random(1401107)
checks=0

def check(z,label):
    global checks
    checks+=1
    if not z: raise AssertionError(label)

def witness(w,b):
    return all(sum((w>>e)&1 for e in s)%2 == b[v] for v,s in enumerate(STARS))

def violations(w,b):
    return tuple(int(sum((w>>e)&1 for e in s)%2 != b[v]) for v,s in enumerate(STARS))

def code(b,k,masks):
    return tuple((k+sum(violations(w,b)[j]*masks[j][w] for j in range(4)))%Q for w in range(NUM))

for w in range(NUM):
    check(not witness(w,FALSE_B),'K4 charged instance is false')
    v=violations(w,FALSE_B)
    j=next(j for j,c in enumerate(v) if c)
    for k in range(Q):
        for anchor in range(Q):
            outcomes=[(k+anchor+v[j]*a)%Q for a in range(Q)]
            check(set(outcomes)==set(range(Q)),'uniform coordinate conditional law')
true_ws=[w for w in range(NUM) if witness(w,TRUE_B)]
check(len(true_ws)==8,'eight uncharged K4 assignments')
for run in range(48):
    masks=tuple(tuple(RNG.randrange(Q) for w in range(NUM)) for _ in range(4))
    k=RNG.randrange(Q)
    ptrue=code(TRUE_B,k,masks)
    pfalse=code(FALSE_B,k,masks)
    for w in true_ws:
        check(ptrue[w]==k,'every valid ORIGINAL witness gets same value')
    for w in range(NUM):
        check(violations(w,FALSE_B)!=(0,0,0,0),'no false-satisfying Boolean point')
    check(len(pfalse)==NUM,'output table length')
for z in range(Q):
    check((z*z-z)%Q==0 if z in (0,1) else (z*z-z)%Q!=0,'Boolean idempotents')
sizes={str(n):7856*(1<<n) for n in (6,16,20,24,32)}
check(sizes['20']==8237613056,'exponential size')
report={
 'run':'R140-BOOLEAN-QUOTIENT-FULL-TABLE-20261107',
 'status':'NON_PRACTICAL_INFORMATION_THEORETIC_REFERENCE_ONLY',
 'field':Q,'variables':len(EDGES),'assignments':NUM,
 'true_witness_count':len(true_ws),'false_witness_count':0,
 'checks':checks,'random_full_table_trials':48,
 'signature_table_bytes':sizes,
 'security_statement':'perfect marginal/joint fixed-FALSE full-table hiding under independent uniform mask values; NOT PPT setup and NOT a generic WKEM',
 'assumptions':'independent uniform full-table masks; no secret checking/auxiliary leakage; sampled classic exact law',
}
print(json.dumps(report,sort_keys=True,separators=(',',':')))
~~~

Actually executed offline Python script was the identical algorithm above with an additional \`checker_sha256\` field computed from the local script's exact bytes; the local script SHA-256 was \`f1c8188fa661d0150e4629ee488657bc02fc6a8fc2cae5e564f44ade378423cf\`. Local independent runnable script and full derivation are preserved in the run's container working archive. The executed script produced **6713 checks** with all passes. Exact captured output:

~~~json
{"assignments":64,"assumptions":"independent uniform full-table masks; no secret checking/auxiliary leakage; sampled classic exact law","checker_sha256":"f1c8188fa661d0150e4629ee488657bc02fc6a8fc2cae5e564f44ade378423cf","checks":6713,"false_witness_count":0,"field":7,"random_full_table_trials":48,"run":"R140-BOOLEAN-QUOTIENT-FULL-TABLE-20261107","security_statement":"perfect marginal/joint fixed-FALSE full-table hiding under independent uniform mask values; NOT PPT setup and NOT a generic WKEM","signature_table_bytes":{"16":514850816,"20":8237613056,"24":131801808896,"32":33741263077376,"6":502784},"status":"NON_PRACTICAL_INFORMATION_THEORETIC_REFERENCE_ONLY","true_witness_count":8,"variables":6}
~~~

**Next iteration:** do not optimize this exponential control; investigate a cryptographically ENFORCED, succinct global Boolean release whose joint public QPT simulator is specified simultaneously with its actual LWE source keys, all openings and auxiliary fields. No ordinary PR comment or user notification for this negative/non-practical control.
