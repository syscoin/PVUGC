# Factor-local torsion SOURCE: universal signed-public-decoder break and failed pairwise-moment repair

## Provenance and verdict

Offline continuation of the existing open/draft/unmerged syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918. Exact starting SHA: ba02acb81da7e477874aa7d24b5c7d04a7aaa6f3. Selected predecessor: factor_local_torsion_source_20261029/RESEARCH.md (Git blob d43f20656b4dd21bb9a192ba1fca092ce8c434f9), check.js (ce86b9064fbc639b2d5396eb5eef16afb62dbfde), and ordinary PR comment 6500023465. Current PR metadata, latest ordinary comments and only those exact-version files were inspected. No external research or unauthorized repository access.

**NO POSITIVE SECURE WITNESS-KEM ADVANCE.** This is a material security correction. The previous factor-local construction is honestly correct for every valid ORIGINAL witness and has genuine certified-FALSE XOR-subsystem security, but its generic 3CNF encryption of every share can be completely decrypted by a PUBLIC polynomial-time algorithm without a witness. The attack also defeats a concrete pairwise-moment strengthening. It does NOT invalidate the separate mod-2 certificate proof for certified-FALSE XOR factors, since an ordinary 3CNF clause has a different integral affine span.

## Exact honest setup/public experiment

Consider an ORIGINAL 3CNF of M clauses, each over three DISTINCT Boolean variables with precisely one forbidden tuple and seven allowed local tuples. This is an explicitly permitted ordinary 3CNF input to the predecessor's compiler, with no 3-XOR truth-table folding. The witness-free classical SOURCE compilation creates one coordinate for each allowed local tuple, an A normalization row for each clause, and spanning-tree rows agreeing on each variable's first Boolean moment across factor occurrences. U has 1 in normalization rows and 0 in agreement rows. Every satisfying ORIGINAL assignment gives a valid one-hot phi with A phi=U over the integers, norm M, and recovery of the SAME precommitted K.

Generate the genuine native keypair (K,pk), choose t independent uniform B-bit XOR shares Z_i and publish Mask=K XOR Z_1 XOR ... XOR Z_t. Every encrypted share bit a uses independent uniform s in Z_q^rows, independent ternary e in {-1,0,1}^columns and eps in {-1,0,1}; choose q=2^k and g=q/2, and publish COMPLETE ciphertext

    c=A^T s+e mod q,
    d=U^T s+eps+g a mod q.

The full-public view also includes relation/statement, claim/UTXO/branch/context binding, actual intended native checking key pk, auxiliary records and related capsules. The attack requires NONE of the optional auxiliaries, related-capsule disclosures, opening or signing queries, or challenge secrets. Therefore failure in this basic included experiment already disproves every-fixed-FALSE full-public security and hard-TRUE unauthorized recovery-to-ORIGINAL-witness security. Its adversary is classical PPT, a subset of arbitrary QPT.

## Universal public signed pseudo-opening and release

Select any PUBLIC Boolean base assignment b. For each 3CNF clause factor j:

- If its base tuple is an allowed one, put one coefficient +1 on that tuple.
- Otherwise its base tuple u is exactly its forbidden tuple. Put +1 on u XOR 100, +1 on u XOR 010, and -1 on u XOR 110 (these three tuples are allowed), with other local coefficients zero.

Every factor's coefficients sum to 1 and, for all three variables, the signed first moment equals b[v] exactly OVER THE INTEGERS. Thus the public signed vector psi satisfies

    A psi=U over Z;
    ||psi||_1=sum_k psi_k^2=M+2 V(b),

where V(b) counts the violated clauses at b. This is not a valid one-hot witness and cannot be required from the adversary. It is synthesized by the attack using public coefficients only.

For EACH full public ciphertext, directly compute

    r=d-psi^T c=g a+eps-psi^T e mod q.

The secret s disappears identically, without solving LWE or recovering an ORIGINAL witness. Independent ternary errors imply

    |eps-psi^T e|<=M+2 V(b)+1.

If q/4>M+2 V(b)+1, cyclic nearest-center decoding (0 versus q/2) recovers EVERY protected share bit under EVERY coin outcome. XORing all shares with Mask recovers the COMPLETE precommitted native signing secret K, whose genuine checking key was already public. This is native-key possession rather than a break of the signature algorithm.

Even if q barely misses this worst-case condition, Hoeffding for the independent centered errors yields

    Pr[wrong one bit] <= 2 exp(-(q/4)^2 / (2(1+M+2 V(b)))),

and union bound multiplies this by t B for all protected bits. Increasing the common bounded ternary-noise scale with the honest correctness threshold does not establish security: the fake decoder has only a constant-factor more independent noise, so cancellation concentration remains on the order sqrt(M), while the signal spacing needed for worst-case all-witness correctness is on the order M.

## No-witness polynomial-time base assignment

A uniformly random assignment falsifies each three-distinct-variable 3CNF clause with probability exactly 1/8, regardless of the literal signs. Fix variables one by one, greedily choosing the value minimizing the conditional expected number of violated clauses. Exact rational conditional expectations are efficiently computable from the clause list and the unfinished variables. The final deterministic b obeys V(b)<=floor(M/8), independently of satisfiability. Therefore all ordinary 3CNF factors have a PUBLIC signed pseudo-opening of norm at most M+2 floor(M/8).

In particular, for M=192, the minimum permitted power-of-two q from the predecessor's requirement q>4(M+1) is q=1024. The pseudo-decoder has absolute noise at most

    M+2 floor(M/8)+1 <=192+48+1=241 < 256=q/4.

Thus EVERY 192-clause ungrouped 3CNF, TRUE OR FALSE, has deterministic whole-key public recovery. The same universal worst-case attack holds for 127<=M<=204 at q=1024. Clauses with distinct three-variable scopes cannot be folded into the predecessor's four-clause XOR groups; the checker constructs 192 distinct scopes. This is a proof for a broad, genuine NP-complete 3CNF SOURCE family, not a single toy false case. It is not a statement about separately certified XOR factors.

## Exact fixed-FALSE 3CNF and complete-ciphertext mock-key recovery

Five ORIGINAL variables (x,y,z,a,b), eight clauses:

    (x OR y OR z)
    (x OR y OR NOT z)
    (x OR NOT y OR z)
    (x OR NOT y OR NOT z)
    (NOT x OR a OR b)
    (NOT x OR a OR NOT b)
    (NOT x OR NOT a OR b)
    (NOT x OR NOT a OR NOT b)

The first four force x=1, last four force x=0, so all 32 ORIGINAL assignments fail. The four forbidden tuples on each shared triple are NOT a parity class and do not form the exact XOR-foldable pattern.

Choose the public b given by conditional expectation. It violates exactly one clause. Degree-1 SOURCE: 27 rows, 56 columns, signed norm 10; q=64 and g=32 satisfy honest completeness (q>4(8+1)), while max public pseudo-decryption noise 11 is strictly below q/4=16. The exact executable checker generates all actual (c,d), samples all uniform s and independent ternary e,eps, and publicly recovers two independent complete 256-bit, three-share mock native secrets with no ORIGINAL witness. Any genuine native key with an identical encrypted byte representation would likewise be disclosed. The checking-key hash in the extended local checker is mock; a native SLH implementation is not claimed.

## Attempted repair: second-order local moments (FAILED)

Add all repeated variable-PAIR moment agreement rows to A as well as ordinary single-variable agreement rows. Every actual ORIGINAL witness remains a correct one-hot opening. Nevertheless, when base u is the forbidden tuple, assign the seven allowed tuples u XOR 1_S (nonempty S subset {1,2,3}) the signed weights

    psi_(u XOR 1_S)=(-1)^(|S|+1).

The Boolean third finite-difference identity proves that these signed weights reproduce EVERY local monomial of degree 0,1,2 at u, over the integers. Thus the corresponding global psi still satisfies A psi=U, including every pair-moment row. On the same fixed-FALSE eight-clause formula, degree-2 SOURCE has 45 rows and 56 columns, signed norm 14, and absolute decoding error at most 15<q/4=16. The checker again publicly recovers two whole 256-bit, three-share mock native secrets with fresh honest coins.

This second-moment modification is not a repair. A higher moment degree may eliminate THIS PARTICULAR example but neither every fixed FALSE generic-NP source nor arbitrary hard-TRUE extraction is proved; repeating another rank or local-moment hierarchy is not the current construction priority. Publicly verifying that a VOLUNTARILY SUBMITTED phi is one-hot also does not prevent the attacker directly computing a linear residual with its signed psi. The previous rowspace-noise and scalar-LWE-wrapper failures still apply.

## Executed evidence and exact versions

Committed check.js is the literal source of a locally executed V8 JavaScript function followed by JSON printing. It passed 12,213 exact assertions and recorded two complete mock-key recoveries at EACH of degrees 1 and 2, checks of both complete ciphertext components, exhaustive FALSE status for 32 assignments, 192 distinct clause scopes, and deterministic conditional-expectation bounds. Its captured output is committed as OUTPUT.json. Independent LOCAL-ONLY Python standard-library check.py passed 12,248 assertions in EACH of TWO byte-identical runs, also recovering two entire mock keys per degree. The randomized 192-clause fixtures are independently seeded (V=1 in JavaScript, V=8 in Python); both verify the general theorem V<=24.

No quantum-computation, quantitative QPT-LWE hardness evaluation, actual SLH signing implementation, on-chain Bitcoin source verifier or malicious N-of-N ceremony was executed. No independent agents were invoked.

## Exact unresolved release replacement and security boundary

The linear release mechanism is not salvageable by a public one-hot check: it computes d-phi^T c, and any efficiently computed signed psi with A psi=U and small error supplies an independent no-witness release. A prospective actual repair must REPLACE THE CRYPTOGRAPHIC RELEASE RULE, not merely impose semantic restrictions on the phi parameter. It must instantiate a witness-free classical polynomial-time source-dependent setup and release operation whose nonlinear validity dependence cannot be bypassed by signed or higher-moment pseudo-openings, together with its SOURCE-correlated standard QPT-LWE challenge simulator (or independently justified hash-based successor). It must preserve EVERY valid ORIGINAL witness -> SAME precommitted capability; every fixed FALSE complete-public QPT security; and arbitrary unauthorized hard TRUE final-key recovery/native forgery -> ACTUAL ORIGINAL W or an INDEPENDENT QPT break, without requiring the adversary to disclose a representation or assuming SourceOpen.

The full view must retain actual checking-key correlations, adversarial auxiliary data and multiple related capsules, ORIGINAL claim/UTXO/branch/anchors/window/context binding, and selective openings. Malicious N-of-N with one honest erasing signer and no bypass edge, abort/funding/presignature/DA graph security, authentic SYS/BTC AuxPoW/header/coinbase/interval evidence and the conditional future no-EC native PQ Bitcoin endpoint remain unproved. Do NOT claim general witness encryption, deployment readiness, 128-bit QPT security or a solved recovery-to-ORIGINAL-witness reduction. **No positive advance meeting the user's progress standard was made; keep the research automation enabled.**
