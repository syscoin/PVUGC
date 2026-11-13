# Ordinary-LWE multi-lift obstruction: source-dependent ORIGINAL witness opening

**Status: NO positive secure generic-NP WKEM construction advance.** A new exact information-theoretic limitation of the native-attested restricted LWE SOURCE is proved below. One attempted public-kernel repair is also rejected. This neither disproves all witness encryption nor undermines the separately established restricted honest-TRUE-LWE ciphertext hybrid or certified-FALSE XOR torsion theorem.

## Exact version and research scope

Existing syscoin/PVUGC PR #1 (open/draft/unmerged), branch research/pq-wkem-validation-20260918, starting head 73c9d3a7c2380b33cb5f2c54afee5189809428f2. Read current PR metadata, latest substantive ordinary comment 6509233897, and exact predecessor research/pq-wkem/native_attested_joint_20261029/RESEARCH.md (blob fd092b3a343a97a413fa504b9b39d48f90956a83). The checker was executed offline twice with byte-identical output. No external source research or independent agent.

## Exact sampler and public-security obligations

Let q be prime, q>2B+1, A uniform in F_q^(n x m), s uniform in F_q^n, e from an independently sampled error distribution chi^m supported on [-B,B]^m. Set b=A^T s+e modulo q and publish H=(A,b). The full public record also includes ORIGINAL relation R, x, claim/UTXO, branch, anchors/window/context, native checking key pk, source and ciphertext parameters, individual contributor ciphertexts, related capsules, permitted auxiliary data, and a genuine native signature attesting to the setup record. The predecessor's restricted QPT theorem assumes honest SOURCE sampling, native EUF-CMA and ordinary QPT decisional LWE; classical adaptive corruption of at most N-1 globally distinct contributors, classical nonchallenge signing queries and independently simulatable auxiliary data. It neither proves SOURCE membership publicly nor handles arbitrary ORIGINAL NP.

The unfinished compiler must be witness-free classical PPT, and for every W satisfying R(x,W)=1, Lift(x,W,H,aux) must supply bounded (s_W,e_W) with b=A^T s_W+e_W mod q, and off-chain Release must reconstruct the same precommitted native signing secret, without requiring the adversary to volunteer a representation. All fixed FALSE statements must have full-public QPT secrecy; unauthorized hard TRUE secret recovery or accepted native forgery must yield an ORIGINAL W or independently justified QPT break.

## Lemma 1: uniqueness of a short SOURCE preimage under planted ordinary LWE

Condition on the planted s,e. For each s' different from s, A^T(s'-s) is independent uniform in F_q^m. There are exactly (2B+1)^m choices of bounded e', hence

    Pr[exists (s',e') with s'!=s and ||e'||inf<=B
       and b=A^T s'+e'] <= (q^n-1)*((2B+1)/q)^m.

For uniformly sampled H=(A,b), irrespective of a planted witness, the analogous existence probability is at most

    P_unif = q^n * ((2B+1)/q)^m.

The derivation is over complete finite-field distributions and applies even to unbounded distinguishers; it does not infer computational LWE hardness. With illustrative but *not QPT calibrated* parameters q=16777213,n=256,m=6800,B=128, log2(P_unif)=-102617.751377 approximately. With overwhelming probability every bounded SOURCE lift on the same planted H has exactly the same s and e, even though distinct ORIGINAL witnesses may remain distinct.

This demonstrates that the standard planted-LWE SOURCE cannot provide multiple independently varying short SOURCE witnesses. Treating every valid ORIGINAL witness as a magic way to compute the same hidden s is itself the unfinished W-gated release problem, not a compiler. It does NOT assert that distinct ORIGINAL witnesses must use identical intermediate states in any eventual alternative construction.

## Lemma 2: H-only joint challenge simulator cannot also support a public known-TRUE Lift

Fix a valid ORIGINAL (x,W) with publicly known W; generic NP coverage includes such easy TRUE instances. Suppose SimAux(H,x,pk,context) is classical PPT using H and independent accessible coins or legitimate nonchallenge signing oracles, never the hidden planted (s,e). Suppose a public classical PPT Lift(W,H,SimAux(...)) returns a bounded valid short preimage with probability at least 1-epsilon when H is planted ordinary LWE.

An ordinary decisional-LWE distinguisher given challenge H runs this very SimAux and Lift with its known W, and checks the finite-field relation and infinity norm. On LWE samples it accepts with probability at least 1-epsilon; on uniform samples it accepts with probability at most P_unif by Lemma 1. Therefore

    Adv_QPT_DecLWE >= 1-epsilon-P_unif.

The distinguisher is actually classical PPT. Consequently the conjunction of ordinary QPT decisional-LWE, known-TRUE public all-witness Lift and an H-only simulatable full public interface cannot hold. Genuine native pk and same-key setup signature do not help: if simulatable from H using independent KeyGen or native signing oracles they are part of the same distinguisher. This lemma does *not* forbid a correlated SOURCE-dependent auxiliary distribution that cannot be simulated using H alone; that missing joint simulation must be proved explicitly rather than assumed. It also does not claim impossibility for hard TRUE instances where W is unavailable to an unauthorized attacker, or for other independently justified assumptions.

## Attempted repair: public affine-kernel SOURCE fiber (failed)

Append a public zero row to A and an extra secret coordinate k. Then (s,k) yields the same b and same ciphertext residual for every k in F_q. An exact q=17 check gives 17 such source preimages, but the extra coordinate is a public kernel direction and a generic W cannot compute the unknown base s. Selecting k=encode(W) does not give a release. Moreover the appended-zero-row source is NOT the full-uniform H distribution of ordinary LWE, so claiming ordinary-LWE security without stating the degenerate reduction would be invalid. No source-dependent nonlinear release or generic ORIGINAL-witness extraction is obtained.

## Reproducible bounded offline checks

The exact Python standard-library-only checker below, RNG seed 20261029, was executed twice with byte-identical output, passing 756 assertions. It exhaustively inspected all 17^2 possible short-source secrets for 240 sampled planted toy cases (q,n,m,B)=(17,2,9,1): each had exactly one preimage. The corresponding 240 uniform-b tests had zero short preimages. It checked all 17 public-kernel alternatives and the stated illustrative large-parameter bound. These toy observations are not quantum-hardness tests, native-PQ signatures, or proof of generic NP security.

## Exact remaining release obligation

Need classical witness-free Comp(R,x,ctx,pk)->(D,auth,aux), with EVERY R(x,W)=1 yielding Release(D,W)=sk_star and PK(sk_star)=pk, while complete joint public records for EVERY fixed FALSE x QPT-hide sk_star and arbitrary unauthorized hard TRUE final-key recovery/native forgery reduces to ORIGINAL W or an independently justified QPT break. The challenge simulator must generate all SOURCE-dependent auxiliaries and checking-key correlations without a secret SourceOpen oracle, cover coherent QPT postprocessing, related capsules and selective openings, and cannot invoke an uninstantiated iO/WE/WPRF/RIO assumption. Malicious N-of-N ceremony, graph/abort/DA, actual SYS/BTC evidence and hypothetical native PQ Bitcoin endpoint remain unresolved. Do not deploy or disable the research automation.

## Exact executed offline checker

    #!/usr/bin/env python3
    """Offline, deterministic arithmetic check of planted-LWE preimage uniqueness
    and a public-nullspace counterproposal. This is not a QPT experiment."""
    import random, json, math, hashlib
    from itertools import product
    
    rng = random.Random(20261029)
    checks = 0
    
    def require(flag, message):
        global checks
        checks += 1
        if not flag:
            raise AssertionError(message)
    
    def row_times(A, s, q):
        return [sum(A[i][j]*s[i] for i in range(len(s)))%q for j in range(len(A[0]))]
    
    def candidate_count(A, b, q, B):
        n=len(A)
        count=0
        out=[]
        for sp in product(range(q), repeat=n):
            projected=row_times(A,sp,q)
            errors=[(bj-aj)%q for bj,aj in zip(b,projected)]
            if all(e<=B or e>=q-B for e in errors):
                count+=1
                out.append(sp)
        return count,out
    
    q,n,m,B = 17,2,9,1
    trials=240
    hist={}
    uniform_accept=0
    for t in range(trials):
        A=[[rng.randrange(q) for _ in range(m)] for __ in range(n)]
        s=tuple(rng.randrange(q) for _ in range(n))
        e=[rng.randrange(-B,B+1) for _ in range(m)]
        b=[(u+v)%q for u,v in zip(row_times(A,s,q),e)]
        cnt, sols=candidate_count(A,b,q,B)
        require(s in sols, 'planted s absent')
        require(cnt>=1, 'no planted solution')
        hist[cnt]=hist.get(cnt,0)+1
        uniform_b=[rng.randrange(q) for _ in range(m)]
        uniform_cnt,_=candidate_count(A, uniform_b, q, B)
        require(uniform_cnt>=0,'bad counter')
        uniform_accept += int(uniform_cnt>0)
    
    # Construct public zero-kernel padding; all q separate secret vectors are valid
    # even though their differences depend on a completely public coordinate.
    q2=17
    A2=[[3,5,2,7,9,4],[0,2,7,1,5,6],[0,0,0,0,0,0]]
    s2=(4,9,0)
    e2=[0]*6
    b2=row_times(A2,s2,q2)
    for k in range(q2):
        sk=(4,9,k)
        require(row_times(A2,sk,q2)==b2,'public-kernel lift not a preimage')
    require(any(row_times(A2,(4,8,k),q2)!=b2 for k in range(q2)),
            'changing non-kernel source secret should change public b')
    
    # Distinct SOURCE states through a public kernel do not derive the *hidden*
    # first two coordinates from a generic ORIGINAL W.
    for k in range(q2):
        require(row_times(A2,(4,9,k),q2)==row_times(A2,(4,9,0),q2),
                'source kernel changed ciphertext decryption')
    
    ub_log2=n*math.log2(q)+m*(math.log2(2*B+1)-math.log2(q))
    qreal=16777213
    nreal,mreal,Breal=256,6800,128
    real_bound=nreal*math.log2(qreal)+mreal*(math.log2(2*Breal+1)-math.log2(qreal))
    require(real_bound< -100000,'instantiated uniqueness bound unexpectedly weak')
    
    print(json.dumps({
        'status':'PASS',
        'checks':checks,
        'seed':20261029,
        'toy':{'q':q,'n':n,'m':m,'B':B,'trials':trials,'preimage_count_histogram':hist,'uniform_accept_count':uniform_accept,
               'log2_union_upper_bound':round(ub_log2,6)},
        'public_kernel':{'q':q2,'distinct_source_preimages':q2,
                         'statement':'all differ in one public null coordinate, not ORIGINAL release'},
        'illustrative_previous_params':{'q':qreal,'n':nreal,'m':mreal,'B':Breal,
                                        'log2_probability_of_any_other_short_secret_upper_bound':round(real_bound,3)},
        'scope':'classical arithmetic/union bound; no QPT hardness, generic NP, or native-signature tests'
    },sort_keys=True,indent=2))
    
## Exact captured stdout

    {
      "checks": 756,
      "illustrative_previous_params": {
        "B": 128,
        "log2_probability_of_any_other_short_secret_upper_bound": -102617.751,
        "m": 6800,
        "n": 256,
        "q": 16777213
      },
      "public_kernel": {
        "distinct_source_preimages": 17,
        "q": 17,
        "statement": "all differ in one public null coordinate, not ORIGINAL release"
      },
      "scope": "classical arithmetic/union bound; no QPT hardness, generic NP, or native-signature tests",
      "seed": 20261029,
      "status": "PASS",
      "toy": {
        "B": 1,
        "log2_union_upper_bound": -14.347577,
        "m": 9,
        "n": 2,
        "preimage_count_histogram": {
          "1": 240
        },
        "q": 17,
        "trials": 240,
        "uniform_accept_count": 0
      }
    }
