# 2026-11-24 UTC — hierarchical state-capability promotion in a witness-dependent subset-sum compiler (NONQUALIFYING)

## Continuity and selection

Actual syscoin/PVUGC PR #1 is open, draft, unmerged, same-repository branch research/pq-wkem-validation-20260918; start 2fac42742374056da8093c9b1ebe111736132938. Read PR metadata, substantive recent comments including R225, exact-head SOURCE_EXTERIOR_TRANSPORT_CYCLE_COVER_20261124.md (blob 64cfba8724c89d872617170ce0cabebdf2209e59), SOURCE_NAMESPACE_GARBLING_SEED_COMPILER_20261124.md and SOURCE_OR_PROOF_CHALLENGE_EXCHANGE_20261124.md. No web, external literature, entire PR diff, historical sweep or new Core source claims.

Missing operation: serialize a classical-PPT witness-blind Build_inc(x_W,sigma_cancel), public Open_inc(C,w) returning the same frozen safe native capability for every qualifying ORIGINAL w, and a full-public FALSE/arbitrary hard-TRUE proof. Keep the complete original source circuit and its three-ground OR unchanged. Symbolically grant a standard polynomial witness-preserving reduction of the complete bounded source verifier to exact positive-integer subset sum (a_1,...,a_n,T) with both witness maps; not an implemented consensus circuit or source reduction.

Mathematical change selected before implementation: replace transport matrices and occurrence labels by one-way, layer-and-exact-partial-sum-indexed GGM state capabilities. A choice d in {0,1} transfers a capability for sum s at layer i to exactly s+d*a_(i+1) at layer i+1; two distinct histories may merge only at the SAME partial sum, which is a sufficient state for the remaining exact-sum computation. No split scalar trace, matrix inverse, accepting row correction, public root for arbitrary full-certificate namespaces or additive private-coefficient evaluator. The prior cycle-cover attack cannot be directly applied to this acyclic state graph with one-way secret transition pads; arbitrary incompatible state splices require obtaining a genuine label for another partial sum. The proposed witness-blind compiler is hierarchical state-subtree transition and promotion, not an independently sampled final correction seed. This is a foundation screen (which cryptographic authority a polynomial capsule can grant), not a bandwidth optimization of a proven primitive.

## Explicit uncompressed candidate and proposed repair

Use b=ceil(log2(T+1)) (at least one), and reject partial sums >T because the weights are positive. At each layer i sample an independent lambda-bit root r_i for a binary GGM tree; denote by k_(i,p) the descendant seed at prefix p, derived by domain-separated hash expansion. For fixed-width b-bit sum s, L_(i,s)=k_(i,enc_b(s)). For each i,s,d with t=s+d*a_(i+1)<=T, publish

    C_(i,s,d) = L_(i+1,t) XOR H_edge(ctx,i,s,d,L_(i,s)).

Publish L_(0,0) and E=sigma_cancel XOR KDF(ctx,L_(n,T),len(sigma_cancel)); do not publish roots. All indices are unambiguous and domain-separated. An original witness maps to a subset of exact weight T; its entire sequence of partial sums remains in range and the corresponding edge capsules return the next genuine labels by induction. Every accepted witness reaches the SAME L_(n,T). The label is obtained by traversing actual sum states, not by an honest-code check after raw key recovery. This is only correctness of an exponential compiler, with no security theorem even for the full table; GGM label correlation, QPT queries and source/auxiliary correlations remain to be handled. It is NOT a classical-PPT Build as the weight bit lengths are polynomial and T can be exponential. Do not count this as a solution.

Attempt to compile the state transitions using dyadic blocks: for a prefix p let B(p) be the aligned interval of sums represented by that prefix. Whenever B(p)+d*a_(i+1) is an aligned block B(q) of the same size, entirely in range, publish the block correction

    D_(i,p,d) = k_(i+1,q) XOR H_block(ctx,i,p,d,k_(i,p)).

A holder of the source subtree seed can recover the entire destination subtree seed and then any destination leaf in it. Splitting misaligned shifts is allowed. This has an actual serialized syntax and public opening algorithm, but a leaf token cannot derive its parent subtree seed through ordinary GGM descent. Merely publishing block corrections does not make them usable by an opener starting with the single leaf for s=0. With only descent and same-size transfers, a singleton never grows; changing shift alignment or using LSB-first carry handling does not fix this directionality. Retaining the individual leaf transitions as fallback gives the exponential table again.

Proposed repair: allow promotion tokens, encrypted under an actual incoming leaf/subtree capability, which output the containing subtree seed at the destination. It is essential that this is a change of cryptographic authority rather than only a more efficient encoding: the holder can descend to ANY leaf in the newly granted block. One possible safe rule is to promote only into blocks contained in the true prefix-reachable set S_i={sum of a subset of first i weights}. Then a holder of any such seed knows only genuine reachable sums at that layer, at least under the intended access semantics. This is not yet a computational security/extraction argument, and Build must generate the needed blocks without enumerating witnesses.

## Exact cover barrier, and a false-instance attack on coarser promotion

For m>=2 choose M=1+2^m and prefix weights M*2^j for j=0,...,m-1. Let A=2^(2m)-1=M(2^m-1). The layer-m reachable states are

    S_m={M*u : 0<=u<2^m}.

Their b=2m bit encodings have two identical m-bit halves. Every non-singleton ordinary prefix subtree containing any such encoding includes an encoding with one of its free bits toggled, which breaks that equality. This holds for any fixed ordering of the individual sum bits. Hence an exact prefix cover needs 2^m singleton blocks when T=A (all prefix sums in range). Changing to coarser prefixes while insisting they contain only S_m is not possible in this example. This is a lower bound on that exact-cover policy, not on arbitrary succinct access structures or a grouped-variable representation.

A more permissive repair might allow promotion to unreachable states when none can finish at the target. Test it on the explicit FALSE instance with the same prefix weights and an identical set of suffix weights, target T=A-1. All full subset sums are multiples of M, so T cannot be reached. At the middle layer, for every s in S_m with s<=T and least significant bit one, define s'=s-1. This is not in S_m. But A-s is in S_m (select the complement of the prefix subset in the suffix), and

    s' + (A-s) = T.

In the natural MSB-first tree, EVERY non-singleton prefix block containing s also contains s' (it leaves at least the last bit free). Thus any promotion giving the opener such a block after an actual valid prefix to s gives the genuine state key L_(m,s') for the unreachable s'. Using the actual suffix transitions for the complementary subset then yields L_(2m,T) and the exact frozen plaintext. Positive suffix weights ensure every intermediate sum is <=T. This attack uses only public corrections and actual derivation from the granted seed; no oracle transcript, hash collision, native signature forgery assumption, representation restriction or source witness. No exact-sum solution exists. For arbitrary fixed bit order independent of the instance, use a target A-2^k where k is the final coordinate in that order, and prefix states having bit k one and s<=T; the same toggling argument applies (no count claimed for a general ordering). No claim of a uniform target defeating an adaptively chosen bit ordering.

In particular the explicit MSB-first instance has exactly 2^(m-1)-1 such dangerous states s<=T. A compiler which insists on preserving ALL prefix-path capabilities even on FALSE instances must issue separate singleton destination capabilities for these states, since every larger block containing one is dangerous. Under the specified token grammar each token yields one fixed destination seed, and descendants are obtained only by GGM expansion; this requires exponentially many distinct singleton grants to those states. A target-dependent compiler could instead prune all these paths because the instance is FALSE (indeed this special instance is easy to recognize); therefore this is not an exponential lower bound for every target-aware compiler, or for the image of the actual source relation. Nor is it a universal barrier to hash-only release. It identifies why this particular subtree promotion mechanism cannot give both full-path correctness and soundness by simply compressing its state space. A more general pruning compiler would need to compute which partial sums can complete an exact target without relying on a private evaluator; in general that is itself a subset-sum extension question, but no hardness claim for specific original instances is inferred.

A distinct repair would represent state sets by grouped equality variables rather than ordinary bit prefixes; the duplicate-half example then compresses trivially. However the proposed GGM transition equation still needs to implement the actual partial-sum addition in that representation without disclosing labels for unreachable, target-completing states, for arbitrary instances in the source reduction. No witness-blind serialized compiler for such transitions or joint simulator is supplied. Do not follow up by changing field/basis/hash placement, tree order, adding more fixtures, or claiming exact prefix cover as an independent advance. The next missing operation is a non-exportable, jointly simulatable state-specific forward label compiler without subtree authority enlargement or an enumerated state graph (or a different non-state-label route).

## Execution and limits

The exact local Python 3 standard-library checker below implements SHA-256 GGM labels, per-leaf edge capsules and the attempted promotion at one boundary. Full tables are intentionally exponential; no polynomial compiler is claimed. It verifies that two distinct genuine witnesses of the TRUE target A recover the same masked message, then demonstrates exact plaintext recovery on the FALSE target A-1 using a promoted parent seed and an ordinary suffix path. m=2,3,4 are merely arithmetic/functional regressions. It also checks the exact dangerous-singleton count for the MSB-first model. Deterministic seeded fixture RNG is not cryptographic production randomness. The fixture omits claim context and models the native capability as random 32-byte message; no real consensus check, native signature, source reduction, QPT experiment or deployment. Executed source SHA-256 d025039343ec23d1f667502e7c5fbbb0ca9322e13aa5e7c1230349fb1f4eab12, stdout SHA-256 a4d581c9a2e550668a52f0978dcd7821defd806c635cb75c34c91860ad9857ae.

No FALSE simulator or arbitrary hard-TRUE recovery/accepted native forgery proof obtained. Preserve full public keys, capsule, native VK/message/context, source commitments, related capsules/selective openings, QPT/nonuniform auxiliaries, malicious source-coin retention, and no adversarial internal state or query log. Preserve original same-anchor strictly greater exact BTC work, finite authenticated specific burn refutation, relevant mature incompatible Syscoin histories / independently authenticated carrier-tag fault, claim/outpoint/amount/recipient/reserve/burn/replay, windows/anchors/depth/deadline/reset, and DA/inclusion assumptions. R316 remains a coverage regression; one-honest N-of-N preauthorization and erasure, malicious capsule correctness before funding, R225 explicit slot-global veto versus genuinely activation-specific native endpoint, off-chain source verification and same-message forgery distinction remain necessary. No source-specific lower bound is asserted. NONQUALIFYING; no ordinary PR comment or user notification.

### Exact executed checker

```python
"""Subset-sum state-label compiler screen; finite SHA-256 functional fixture only."""
import hashlib
import random

rng = random.Random(20261124)

def enc(*parts):
    return b''.join(len(x).to_bytes(4,'big')+x for x in parts)

def h(*parts):
    return hashlib.sha256(enc(*parts)).digest()

def u(x):
    return x.to_bytes(8,'big')

def xor(a,b):
    assert len(a)==len(b)
    return bytes(x^y for x,y in zip(a,b))

def descend(seed, bits):
    for bit in bits:
        seed=h(b'tree-child',seed,bytes([int(bit)]))
    return seed

def prefix(s,b):
    return format(s,f'0{b}b')

def pad(i,s,d,seed):
    return h(b'edge',u(i),u(s),u(d),seed)

def build(a,T,mid,promote):
    # Deliberately exponential edge table. Promotion is the attempted
    # hierarchical compression of the boundary's state capabilities.
    b=max(1,T.bit_length())
    roots=[rng.randbytes(32) for _ in range(len(a)+1)]
    def label(i,s):
        return descend(roots[i],prefix(s,b))
    c={}
    for i,v in enumerate(a):
        for s in range(T+1):
            for d in (0,1):
                t=s+d*v
                if t>T: continue
                p=prefix(t,b)
                if promote and i+1==mid:
                    p=p[:-1]
                dst=descend(roots[i+1],p)
                c[i,s,d]=xor(dst,pad(i,s,d,label(i,s)))
    msg=rng.randbytes(32)
    e=xor(msg,h(b'final',label(len(a),T)))
    return (a,T,mid,promote,b,label(0,0),c,e),msg

def step(cap,i,s,d,label):
    a,T,mid,promote,b,_,c,_=cap
    t=s+d*a[i]
    token=xor(c[i,s,d],pad(i,s,d,label))
    return t,token

def open_path(cap,ds,splice=False):
    a,T,mid,promote,b,L,c,e=cap
    s=0
    for i,d in enumerate(ds):
        s,L=step(cap,i,s,d,L)
        if promote and i+1==mid:
            if splice:
                assert s&1
                s-=1
            L=descend(L,prefix(s,b)[-1:])
    assert s==T
    return xor(e,h(b'final',L))

def reachable(a):
    S={0}
    for v in a:
        S |= {s+v for s in S}
    return S

for m in (2,3,4):
    M=1+(1<<m)
    A=(1<<(2*m))-1
    w=[M*(1<<j) for j in range(m)]
    a=w+w
    T=A-1
    assert T%M and T not in reachable(a)
    S=reachable(w)
    dangerous=[s for s in S if s<=T and s&1]
    assert len(dangerous)==(1<<(m-1))-1
    for s in dangerous:
        assert s-1 not in S
        assert A-s in S
        assert (s-1)+(A-s)==T
        # Every non-singleton MSB-prefix block containing s contains s-1.
        assert prefix(s,2*m)[:-1]==prefix(s-1,2*m)[:-1]
    true_cap,msg=build(a,A,m,True)
    assert open_path(true_cap,[1]*m+[0]*m)==msg
    assert open_path(true_cap,[0]*m+[1]*m)==msg
    false_cap,msg=build(a,T,m,True)
    ds=[1]+[0]*(m-1)+[0]+[1]*(m-1)
    assert sum(d*v for d,v in zip(ds,a))==A!=T
    assert open_path(false_cap,ds,splice=True)==msg
    print(f'm={m}, false={T not in reachable(a)}, dangerous_singletons={len(dangerous)}, '
          f'two_true_witnesses_same_message=True, promoted_false_exact_message=True')
```

### Captured stdout

```text
m=2, false=True, dangerous_singletons=1, two_true_witnesses_same_message=True, promoted_false_exact_message=True
m=3, false=True, dangerous_singletons=3, two_true_witnesses_same_message=True, promoted_false_exact_message=True
m=4, false=True, dangerous_singletons=7, two_true_witnesses_same_message=True, promoted_false_exact_message=True
```
