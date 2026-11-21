# SAI100 — source-correlated lookup-token screen (NONQUALIFYING)

## Provenance and exact task

This execution read the actual open draft syscoin/PVUGC#1 head `c6eb2591d4e27c81139f68db4a912873e21178b3` on `research/pq-wkem-validation-20260918`, its SAI99 note blob `e6ba6ae7772591bd0257f902077809c5e6d5b137` and SAI98 blob `bf31aea31ada276f62bfb345fd4611bac8a2470c`. The targeted issue comments since 2026-11-18 19:24 UTC returned [] at the start of the run. Core #609 source and tests were not rerun; no general hash-only FE/WE is claimed. The original three OR grounds, modern contextual AuxPoW, actual LC maturity, claim prefix, strict native cancellation and all adversarial-source restrictions remain unchanged.

SAI99 tried a hidden common proof token but did not implement public Token/Sim. This screen asks a different concrete question: could the needed source-conditioned release be supplied by a **small hash-only table of hidden lookup labels chosen during setup**, rather than a simulated proof token, affine interpolation, reusable garbled gate or publicly callable invalid-trace pad?

## Concrete restricted public Build/Open attempt

Let (H_{tag},H_{pad}) be domain-separated SHA256-like random oracles in the *explicit ideal classical model* below. Setup has a frozen secret (S\in\{0,1\}^{256}) and a source statement (x_W), chooses (m) different hidden points (B=\{b_1,...,b_m\}\subseteq\{0,1\}^n), and publishes the serialized capsule

[
C=(x_W,\{(t_i,d_i)\}_{i=1}^m),\quad
t_i=H_{tag}(b_i),\quad d_i=S\oplus H_{pad}(b_i).
]

For a proposed ORIGINAL witness (w), the public opener derives at most (q) query candidates (Q_x(w)=\{g_j(x_W,w)\}) from **actual authenticated source bytes**, computes tags, and if a tag matches, computes (d_i\oplus H_{pad}(g_j(x_W,w))). It must also apply the complete ORIGINAL relation and exact safe native message binding; a wrapper-only test cannot repair incorrect token matches, because the capsule is fully public. This is a concrete polynomial-size hash-only public-lookup capsule, but NOT a correct original WKEM.

**Exact missing operation:** Build must choose a small hidden B before future evidence is known, such that EVERY qualifying original witness finds at least one b in B, while no unauthorized public algorithm can recover a b without a qualifying ORIGINAL certificate. No such source-dependent selection algorithm is known here.

## Exact independent-source completeness bound

Under the deliberately narrow model that (i) B is a uniformly chosen m-subset of an N=2^n-point universe, and (ii) for each independently generated future qualifying witness its q distinct candidate points are fixed independently of B (or uniformly sampled without replacement independently of B), the exact success probability is

[
\Pr[B\cap Q_x(w)\neq\varnothing]
=1-\frac{\binom{N-m}{q}}{\binom Nq}
\le\frac{mq}{N}.
]

Proof: A q-subset avoiding B is one of \(\binom{N-m}{q}\) among \(\binom Nq\) equally likely q-subsets. Union bound gives mq/N. This applies only to lookup-point independence; source histories may have correlations outside this model. In particular it is **not** a general lower bound on source-specific computational WE/FE, nor a hash-security theorem for concrete SHA.

The same model gives an attractive restricted **classical** FALSE/full-public hiding observation: before any (H_{pad}(b_i)) is queried, the d_i are independent uniform masks for the fixed S, even jointly with independent tag-oracle outputs. But this is conditional and does not cover adaptive inversion, structured source predicates, arbitrary auxiliary information or QPT coherent queries. More importantly, it does not fix the catastrophic honest completeness probability above.

## Concrete repair decisions

1. Make b_i publicly derivable from the shared Syscoin baseline or existing canonical tag: watcher completeness becomes easy, but any adversary computes the pad and S without a fork, even if `Open` itself checks authenticity. The tag's exact 41-byte syntax authenticates the *source statement*, not a secret release key.
2. Choose b_i from future parent PoW hashes: Build cannot enumerate or predict the actual future headers, so the small setup table almost certainly misses some qualifying original witness. A prefix-constrained PRF seed on *digest outputs* allows anyone to choose a qualifying digest directly without furnishing its SHA preimage or an authenticated source history. That is the forbidden independent target-prefix puzzle shortcut, not a repair.
3. Publish many entries or a generic small circuit computing the hidden pads for all possible original certificates: an explicit full table is exponential; a publicly readable circuit leaking pad constants is unsafe; a genuinely cryptographically concealed verifier-and-release circuit is precisely the unconstructed FE/WE-type operation. These are **screening outcomes**, not instantiated security claims.

Even if an attacker obtained a hidden b_i only after a massive tag preimage search, the extracted object would be b_i, **not** necessarily an actual original Bitcoin/Syscoin certificate. Thus this hash-puzzle family cannot honestly support the required recovery-to-ORIGINAL work theorem just by pricing the hash search to the estimated fork-mining budget.

## Executed bounded calculation

`check.py` uses exact Python integer binomial ratios and checks the union bound at n=8,10,12,14, including an independent exhaustive two-query census at n=8. The checker ran twice, outputs were byte-identical, with exit code 0 in both runs. This validates the elementary finite combinatorics only, NOT SHA, AuxPoW, native signing, a source-work distribution, FE, QPT, or original-certificate authentication.

Locally measured SHA256 of checker: `736221482aea92ab41fac2d23d1846e818413ec90a4cee81369f2fdd03792f2b`; JSON output: `4b42ad70242dc8010a9604b69bcc8658fee01fdaa7a5b9008487444eb43c3d73`. GitHub-stored exact bytes are checked by subsequent file readback. No external web was used.

## Disposition / next exact missing equation

**Reject** independent setup-selected hash lookup labels as an ORIGINAL all-witness release carrier. Do not revisit via merely increasing table size, target-prefix tuning, local hashes, or storing more random points. The executable construction is correct only when an authenticated future w happens to hit B; it does not satisfy required completeness and cannot support an ORIGINAL-certificate extractor. No result warrants user breakthrough notification.

Still needed: a genuinely serialized classical-PPT `Build_original(x_W,S)->C` and public `Open_original(C,w)=S` for all valid original w, with a **joint full-public** false/hard-true QPT reduction producing an actual qualified ORIGINAL certificate (or an independent justified hash/native break) from unauthorized recovery. It must be cryptographically source dependent and sound against arbitrary processing, not an independent puzzle or renamed ideal FE. N-of-N one-honest malicious-setup and native message binding remain additional obligations. No PR progress comment, production change, transfer, deployment or automation change.
