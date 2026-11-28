# One-honest SOURCE-separated safety component, not ORIGINAL-NP witness-KEM

**Status.** A restricted, concrete source-separation construction eliminates the specific malicious *shared-SOURCE retained-opening bypass*, assuming one independently honest source/signing-key owner and an ABSTRACT N-of-N native signature acceptance gate. It does **not** solve generic NP witness release, one-honest funded-graph completeness, or Bitcoin script support. No unknown designated honest LAST verifier, public SOURCE-membership certificate, global shared SOURCE, common preimage, iO/WPRF assumption or quantum rewinding is used.

## Provenance, chosen unfinished step, no external research

Run source_separated_one_honest_20261030. syscoin/PVUGC PR #1, existing branch research/pq-wkem-validation-20260918, starting and exact-file read SHA 699e162850b93864d2e5d1ccc8484b2077c1ca4d; latest substantive ordinary comment 6514574230. Relevant exact-version sources inspected: signed_ternary_triple_lwe_20261029/RESEARCH.md, unique_source_lift_20261029/RESEARCH_AND_CHECKER.md (blob 47e5ba4a8f4bf239ec5135c83a71e34a8e3b0041), native_attested_joint_20261029/RESEARCH.md (fd092b3a343a97a413fa504b9b39d48f90956a83), late_share_shared_crs_20261029/RESEARCH.md. No PR-wide diff, outside literature, outside repository writes, agent or internet research. The specific earlier bypass: a corrupt dealer creating H=(A,b) with known short (s,e), even b=0, can open *all* contributors' ciphers under that H. A valid SOURCE-membership certificate does not prevent it.

## Exact restricted construction (classical PPT)

Use N participants indexed 1..N. Each i independently owns a full native signing key (sk_i,pk_i) and its OWN SOURCE H_i=(A_i,b_i). An honest h chooses uniform A_h in F_q^{n×m}, uniform s_h in F_q^n, e_h from chi^m with support [-B,B]^m, and b_h=A_h^T s_h+e_h mod q. It creates the genuine native checking key pk_h from sk_h and erases/protects sk_h,s_h,e_h and its encryption coins after a validated pre-funding ceremony. All other participants may collude, deliberately publish b_i=0 with known witness (0,0), retain all coins/secrets, or pick sources/related capsules adaptively after seeing H_h. They never overwrite the authenticated independent h slot. No participant's SOURCE witness is available to decrypt another independent participant's ciphertext by design.

Let T be uniformly sampled signed constant-weight vectors r in {-1,0,+1}^m having exactly w nonzeros, |T|=binom(m,w)2^w. Use prime q>2, ell bits/digit, g=floor(q/2^ell). Sample fresh independent r_{i,j,l} for every participant, digit l and same-scope related capsule j=1..J; choose canonical bounded-rejection uniform sampling and abort before funding if the polynomial cap is exceeded. Encode the COMPLETE serialized native secret sk_i into L_i=ceil(bits_i/ell) digits a in [0,2^ell−1] (padding checked). Participant i publishes

    u_{i,j,l}=A_i r_{i,j,l},   v_{i,j,l}=b_i^T r_{i,j,l}+g a_{i,l} mod q.

For every valid bounded SOURCE witness (s',e') of the *same* H_i, off-chain decrypt computes

    d_l=v_l−s'^T u_l = g a_{i,l}+e'^T r_l (mod q),
    |e'^T r_l| <= w B.

Since circular adjacent centers have gap ≥g, strict g>2wB yields deterministic unique nearest-center decoding of every digit, for every valid SOURCE witness and every independently sampled related capsule. Release verifies the rebuilt native pk_i; all valid SOURCE witnesses get the SAME precommitted sk_i for their slot. **There is no instantiated Lift(ORIGINAL W -> honest (s_h,e_h)).**

A complete context-scoped public record contains relation identity/x, claim/UTXO, branch, anchors/window, path, N actual native pks, N public SOURCEs, every individual cipher, auxiliary data and related capsules. Actual sk_i sign an off-chain SETUP-ATTEST canonical transcript domain disjoint from actual challenge sighashes; honest h signs only after all graph/bypass and DA checks it can perform. The native challenge gate is the abstract predicate AND_i Native.Verify(pk_i, exact_same_challenge_sighash, sig_i). No aggregation, tiny PQ sig, on-chain NP check, CAT, adaptor arithmetic, introspection or fake native public key is assumed. The *extra* capability to enforce N independent native SLH-like signature verifications on a hypothetical Bitcoin challenge path is **not granted or demonstrated** by the original P2MR-like assumption. This candidate changes the previous one-key endpoint and is not deployment-ready.

## Full joint QPT security opportunities actually established (restricted SOURCE)

Let nonuniform QPT adversary have advice independent of honest secret sampling, arbitrary coherent processing of all *classical* public sources/capsules/pks/authenticated setup records/context, adaptively malicious other participants and their disclosed witnesses/key material, J independently seeded related h capsules, simulatable auxiliary data, classical nonchallenge setup/native signing queries (never the exact challenge), but no h source/seed/coin leakage, no h decryption oracle, no superposition signing/corruption queries. The same h must remain uncorrupted globally. Honest classical source generation uses exactly the ordinary decisional-QPT-LWE distribution for q,n,m,chi; native key independently uses the actual nonuniform-QPT-EUF-CMA security experiment, with classical signing oracle. The third ingredient is exact universal linear hashing of uniform H_i r over T; these assumptions are independent of an NP-release assumption. No numerical 128-bit concrete hardness is inferred.

**Lemma A: retained malicious SOURCE opening cannot be transplanted to h.** Given challenge H_h either planted LWE or uniform, generate a genuine native sk_h, all honest ciphers and signatures directly using the supplied H_h, and run every adaptively chosen corrupt participant. If it outputs ANY bounded opening (s',e') of H_h, check b_h=A_h^T s'+e'. For uniform b_h the existence probability is at most eps_SRC=min(1, q^n ((2B+1)/q)^m), independent of every subsequent adversarial channel. Thus explicit h SOURCE-opening success ≤ Adv_QPT-DecLWE+eps_SRC. This statement alone does not claim an arbitrary final-key attacker outputs a SOURCE witness.

**Lemma B: final native N-of-N challenge forgery without requiring an internal representation.** Fix one surviving h. G0->G1 replaces only honestly sampled H_h by uniform; all genuine pk/signature and corrupt adaptive public correlations are generated by an efficient QPT channel applied to the full challenge, costing Adv_QPT-DecLWE. For uniform H_h, distinct signed-ternary r imply distinct nonzero differences mod prime q, so universal hashing gives TV((H_h,H_h r),(H_h,U))≤δ_T=0.5 sqrt((q^{n+1}-1)/|T|). Replacing each h ciphertext of genuine sk_h digits with zero encryptions costs ≤2 J L_h δ_T even given same source, genuine checking key, arbitrary other corrupt source/cipher records and related capsules. Re-sign the FULL actual public setup transcript in each game, which is a statistical-data-processing channel; no signature correlation is dropped.

In G2, embed the REAL EUF-CMA challenger pk_h (unknown sk_h), sample uniform H_h, publish only zero encryptions for h, and answer allowed setup-domain and other nonchallenge signature queries using the challenger signing oracle. Malicious participants can choose their own pks/H_i/signatures arbitrarily. Accepted complete N-of-N signatures on an unqueried target give a valid fresh sig_h, directly breaking native EUF-CMA. If an adversary recovers usable sk_h, it signs the fresh target and does the same. No SOURCE representation is requested. Therefore for fixed h,

    Pr[unauthorized accepted N-of-N native challenge] ≤
      Adv_QPT-DecLWE + 2 J L_h δ_T + Adv_QPT-Native-EUF-CMA.

For an unspecified globally uncorrupted survivor among N, an explicit N-factor union/guess loss suffices. This is an early-authentication safety theorem for an ABSTRACT N-native-signature gate. It does **not** prove a generic ORIGINAL-NP WKEM, public SOURCE soundness, or any deployed script. Selective corruption of h makes the h-event false; permitted other-member corruptions disclose their complete source/seed/coin data. Malicious source adaptation is included as efficient postprocessing of h's public data, never as a decryption oracle.

## Exact cost and correctness check (not PQ validation)

At illustrative, uncalibrated q=16777213, n=256,m=6800,B=128,w=2000,N=4, one SOURCE has noise ≤wB=256000 so five bits/digit work: floor(q/32)=524287>512000, but six bits fail. Prior shared aggregated N=4 SOURCE needs noise ≤NwB=1024000 so only three bits work: floor(q/8)=2097151>2048000 but four bits fail. For a *256-bit illustrative native secret*, four separated h-indexed 5-bit ciphertexts cost 160368 bytes vs previous N=4 aggregate 3-bit contributions 265224 bytes. HOWEVER SOURCE storage QUADRUPLES to 20971200 bytes versus 5242800 bytes, and N ordinary native signatures must verify rather than one. Toy/illustrative not concrete SLH performance. At these numerical parameters log2 δ_T≈−885.257 and log2 eps_SRC≈−102617.751, but this is not a QPT-LWE hardness estimate. The source-free nonzero opening is not obtained from W.

**Why this is not the requested final safety + liveness theorem.** Other corrupt participants may make invalid SOURCEs or unreleasable key capsules, and the honest participant does not yet have a source-to-ORIGINAL public correctness checker that would force pre-funding abort. Even the honest H_h remains impossible to open from qualifying SYS/BTC ORIGINAL evidence W by any instantiated algorithm. Thus erasure makes the honest signing key unavailable after genuine W: useful completeness is NOT established. The one-honest N-of-N funding graph, no-bypass edges, pre-signatures/DA, malicious abort, actual SYS/BTC fork/interval validation, censorship conditions and conditional native PQ Bitcoin endpoint remain unresolved. The final missing equation is classical PPT witness-free Comp(R_original,x,claim/context) together with a jointly simulatable ORIGINAL-W-dependent Open_i satisfying **for every valid ORIGINAL W** Release_i(D,W)=the same precommitted native capability (for every key slot), with FALSE full-public QPT security and arbitrary hard-TRUE unauthorized recovery/forgery -> ORIGINAL W or independent PQ break. No SourceOpen oracle, common preimage, inner-SNARG-only extraction, iO/WE or unrelated SOURCE promise may be substituted.

## Reproducible exact executed compact checker

The Python 3 standard-library code below was executed twice identically (source file check_compact.py, SHA-256 9274194a3fdf11eaa565ea7b1334f0c4c24676008750fa0a45c78940a4caa36f, 2408 bytes including final LF). It verifies 294 classical functional/arithmetic assertions over all N=4 possible honest slots, J=2 capsules, an intentionally known-opening corrupt shared-source bypass control, independent honest SOURCE opening/recovery, and exact bounds/byte counts. The separate **local archive** also preserves a longer RESEARCH.md and check.py with 5,841 passing assertions twice, using classical Ed25519 via cryptography 46.0.4 as a *NON-PQ functional mock*, genuine setup-key/checking-key correlations and N-of-N signatures. Neither checker is quantum security evidence. No independent research agents or outside sources were used.

```python
import json, math, random
r=random.Random(2026103002); checks=0
q,n,m,B,w,k,N,J=257,2,12,1,2,5,4,2
g=q//(1<<k)
def ck(x):
 global checks
 checks+=1
 assert x

def honest_source():
 A=[[r.randrange(q) for _ in range(m)] for _ in range(n)]
 s=[r.randrange(q) for _ in range(n)]
 e=[r.choice((-1,0,1)) for _ in range(m)]
 b=[(sum(A[i][j]*s[i] for i in range(n))+e[j])%q for j in range(m)]
 return (A,b),(s,e)

def ciphertext(H,a):
 A,b=H; t=[0]*m
 for j in r.sample(range(m),w): t[j]=r.choice((-1,1))
 return ([sum(x*y for x,y in zip(row,t))%q for row in A],(sum(x*y for x,y in zip(b,t))+g*a)%q)

def open_digit(H,c,S):
 A,b=H; s,e=S
 ck(all((sum(A[i][j]*s[i] for i in range(n))+e[j]-b[j])%q==0 for j in range(m)))
 u,v=c; d=(v-sum(x*y for x,y in zip(u,s)))%q
 dist=lambda x:min(x%q,(-x)%q)
 return min(range(1<<k),key=lambda a:dist(d-g*a))

ck(g>2*w*B)
for h in range(N):
 H,S=honest_source()
 mal=([[r.randrange(q) for _ in range(m)] for _ in range(n)],[0]*m)
 mal_open=([0]*n,[0]*m)
 ck(all(x==0 for x in mal[1]))
 ck(any(H[1][j]!=0 for j in range(m)))
 for j in range(J):
  digits=[r.randrange(1<<k) for _ in range(16)]
  # Shared malicious SOURCE: the corrupt opening recovers the honest key early.
  shared=[ciphertext(mal,d) for d in digits]
  ck([open_digit(mal,c,mal_open) for c in shared]==digits)
  # Source-separated honest SOURCE: any valid honest opening recovers same digits.
  protected=[ciphertext(H,d) for d in digits]
  ck([open_digit(H,c,S) for c in protected]==digits)
  ck(not all((sum(H[0][i][a]*mal_open[0][i] for i in range(n))+mal_open[1][a]-H[1][a])%q==0 for a in range(m)))

Q=16777213; nn=256; mm=6800; ww=2000; bb=128; count=256
logT=(math.lgamma(mm+1)-math.lgamma(ww+1)-math.lgamma(mm-ww+1))/math.log(2)+ww
ck(Q//32>2*ww*bb); ck(Q//64<=2*ww*bb); ck(Q//8>2*N*ww*bb)
ck(Q//16<=2*N*ww*bb)
old=N*((count+2)//3)*(nn+1)*3
new=N*((count+4)//5)*(nn+1)*3
logF=nn*math.log2(Q)+mm*(math.log2(2*bb+1)-math.log2(Q))
ck(logF<-100000)
print(json.dumps(dict(status='PASS',assertions=checks,honest_positions=N,related_capsules=J,
  corrupt_shared_opening='succeeds',independent_corrupt_opening='invalid',
  three_bit_aggregate_ciphertext_bytes=old,five_bit_separated_ciphertext_bytes=new,
  four_source_storage_bytes=N*(nn+1)*mm*3,log2_uniform_short_opening_bound=round(logF,3),
  scope='toy functional and exact arithmetic only; not QPT, native-PQ, ORIGINAL release or Bitcoin'),sort_keys=True))
```

## Captured checker stdout (identical twice)

```json
{"assertions": 294, "corrupt_shared_opening": "succeeds", "five_bit_separated_ciphertext_bytes": 160368, "four_source_storage_bytes": 20971200, "honest_positions": 4, "independent_corrupt_opening": "invalid", "log2_uniform_short_opening_bound": -102617.751, "related_capsules": 2, "scope": "toy functional and exact arithmetic only; not QPT, native-PQ, ORIGINAL release or Bitcoin", "status": "PASS", "three_bit_aggregate_ciphertext_bytes": 265224}
```
