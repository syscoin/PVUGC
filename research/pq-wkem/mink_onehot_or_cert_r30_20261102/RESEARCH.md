# R30 MINK-ONEHOT-OR-CERT — degree-independent k-way certified-FALSE SOURCE composition

**Status: restricted constructive advance, NOT generic post-quantum witness-KEM.** Continuation of R29's genuine 3CNF OR-gadget selector certificate. Instead of nesting binary OR gadgets, an actual ORIGINAL k-way OR has a one-hot thermometer selector with a *constant-degree* polynomial certificate. For polynomially many branches whose false subrelations have polynomial-size bounded-degree publicly checked refutations, the resulting honest SOURCE has an explicit release algorithm and an exact QPT straight-line simulator for its **complete permitted correlated public output**. This does not solve general adversarial FALSE security, hard-TRUE recovered key/native forgery -> ORIGINAL witness, N-of-N malicious setup or the Bitcoin-native endpoint.

Provenance: offline bounded R30 research on 2026-11-02, syscoin/PVUGC PR #1, branch `research/pq-wkem-validation-20260918`, starting verified SHA `3efd9e1b7ad4c1caa0fb7b520561619f7915d52b`, open/draft/unmerged; latest prior substantive ordinary comment `6594964037`. Read only exact R29 research/checker at that version; no external research or whole-PR replay. Published `INDEPENDENT_CHECKER.js` is byte-identical to the locally executed Node checker (Git blob ba2ab14e91ef2b513883d79656f6b1d3b5598a5f). Extended independently executed Python source/outputs and longer derivation are preserved in the run's offline archive, not misrepresented as published file bytes.

## Honest ORIGINAL relation: actual 3CNF one-hot OR

For branches `F_i(v_i)` (each an arbitrary ORIGINAL 3CNF, potentially compiled from generic NP with authenticated statement bindings), introduce Boolean thermometer `u_0,...,u_k` and selectors `t_1,...,t_k`. Genuine clauses require `u_0=0,u_k=1`, and for each i:

```
(!u_{i-1} OR u_i)
(!t_i OR u_i)
(!t_i OR !u_{i-1})
(!u_i OR u_{i-1} OR t_i)
```

Thus `t_i=1` exactly at the unique thermometer transition. A branch clause `l1 OR l2 OR l3` is enabled only if t_i=1, using genuine auxiliary a_ij and **two original 3CNF clauses** `(!t_i OR l1 OR a_ij)` and `(!a_ij OR l2 OR l3)`. All selectors and auxiliaries are genuine ORIGINAL witness bits, not invented representation coordinates. A valid ORIGINAL witness selects exactly one satisfied branch. Other branches and their variables can retain distinct states. Claim/UTXO, relation ID, anchors/window, intended challenge path, native vk and context must be bound into the ORIGINAL instance x and source context. Bitcoin itself verifies none of these general NP computations.

## New bounded-degree selector identity

In the squarefree Boolean quotient algebra over an odd prime field, put `a=u_{i-1}, b=u_i, c=t_i`. The actual four clause-failure polynomials are:

```
f1=a(1-b); f2=c(1-b); f3=ac; f4=b(1-a)(1-c).
```

An **exact integer squarefree polynomial identity** is

```
              c-b+a = f1+f2+b*f3-f4.                  (1)
```

Summing (1) telescopes. The actual endpoint unit-clause failures `u_0` and `1-u_k` yield the explicit identity

```
 1 = SUM_i t_i - SUM_i(f1_i+f2_i+u_i*f3_i-f4_i)
     + u_0+(1-u_k).                                    (2)
```

Therefore `1-SUM_i t_i` lies in the actual selection failure-polynomial mask span using monomial multipliers of degree at most ONE, **independent of k**. This is a genuine relation identity; it does not assume common witness states or an inner proof-of-knowledge extractor.

For branch clause failure `f_ij=x*y*z`, its two genuine guard-gadget failures are

```
g1_ij=t_i*x*(1-a_ij);  g2_ij=a_ij*y*z.
t_i*f_ij=(y*z)*g1_ij+(t_i*x)*g2_ij.                   (3)
```

Suppose every false branch F_i has a **publicly supplied, algebraically verified** degree-d_i polynomial-size certificate `1=SUM_j Q_ij*f_ij`. Equation (3) gives

```
t_i=SUM_j Q_ij*((y*z)*g1_ij+(t_i*x)*g2_ij).          (4)
```

Combining (2),(4), expand polynomial multipliers into squarefree monomials to construct, rather than assume, an explicit certificate

```
          B_D alpha=e_empty,    D=max(1,max_i(d_i+2)). (5)
```

Here B_D contains all true ORIGINAL clause-failure polynomials multiplied by every monomial of degree <=D. The degree does not increase with the number k of branches when d_i stay bounded. Certificate construction costs polynomial time for fixed D and polynomial-length input certificates. This is a k-way composition of **certified** FALSE sources, not a general efficient algorithm to find certificates for all FALSE instances.

## Actual source release and every ORIGINAL witness correctness

Classical honest Build chooses a native signing capability K bound to actual native vk (conditionally supported by a native PQ signature scheme) and encodes each of its bits mu. Let q be an odd prime, Delta a decoding offset, independently sampled uniform mask r_mu in F_q for every B_D column, and independently sampled centered small coefficient noise e_mu. Publish off-chain

```
        C_mu=B_D*r_mu + Delta*mu*e_empty + e_mu (mod q). (6)
```

For every valid ORIGINAL witness w, the evaluation vector lambda_w over *all* source coefficient monomials satisfies lambda_w B_D=0, so

```
        lambda_w C_mu=Delta*mu+lambda_w e_mu (mod q).     (7)
```

Every ORIGINAL witness, even with different branch and auxiliary states, recovers the SAME precommitted K if noise is simultaneously decodable. In particular with M coefficient rows and |e_m|<=eta, ALL witnesses satisfy |lambda_w e|<=M*eta; choosing min(Delta,q-Delta)/2>M*eta gives deterministic all-witness correctness. The R23 independent-noise all-witness tail bound is an alternative under its exact assumptions. All large evidence remains off chain and an ordinary native signature is issued on the path-specific message after capability recovery. No online release authority, common preimage or canonical witness is used.

## Exact permitted full-joint FALSE simulator, QPT model

The full public view is x (ORIGINAL relation and claim, anchors/window, UTXO, branch/path), native vk, source C, checking key/metadata, context, auxiliary inputs and polynomially many independent-base or publicly derived same-base related capsules. Native (vk,K) is generated by a classical PPT native signature scheme **assumed QPT-EUF-CMA**. All mask vectors and coefficient noises are independently sampled by classical PPT Build; checking-key and auxiliary fields must be independently reproducible from the available public view, public random coins and challenge vk without knowing K or hidden r. Allowed external quantum side information is independent of fresh honest mask coins conditional on relevant public/externally provided data. Private target-mask opening, adversarially secret-correlated CK, shared target native signing secrets across independently opened scopes, arbitrary source-opening data and malicious graph ceremony are EXCLUDED.

For every FALSE k-way input with **actual checked certificates (5)**, a simulator receiving the native signing challenge vk but NOT K samples uniform `r'_mu` and honest e_mu, publishes

```
                  C'_mu=B_D*r'_mu+e_mu.                   (8)
```

Couple the honest and simulated masks by `r'_mu=r_mu+Delta*mu*alpha`. Because B_D alpha=e_empty, C'_mu=C_mu **as vectors**. Translation preserves the uniform r distribution, even conditional on vk and the allowed side information. This is exact equality of the *joint* protected-bit classical transcript, not a marginal LWE hybrid. Publicly reproducible CK/aux/context and R22 deterministic same-base derivatives are functions of identical protected data. For independently keyed other scopes, a straight-line simulator can generate and selectively open them, and for independent protected scopes it can use one alpha shift per scope and bit. The same proof holds under arbitrary coherent QPT joint processing of this classical transcript with allowed quantum side information, without rewinding or random-oracle extraction. Target base private openings and correlated hidden-r checking keys are NOT simulated.

Consequently, in that restricted certified-FALSE game an unauthorized accepted native signature for a new challenge-path message can be passed directly to the QPT-EUF-CMA challenger. This does NOT give a reduction for arbitrary adversarial FALSE inputs or hard TRUE x. In particular SOURCE B_D is algebraically structured, not a uniform standard-LWE challenge, and the result cannot be inflated into an ordinary-QPT-LWE joint-output proof.

## Executed checks (not hardness experiments)

The locally executed standard-library Python checker constructs the actual 3CNF failures and an expanded sparse coefficient certificate for k=3,4,5 disjoint copies of R29's explicit degree-one-refutable nine-clause FALSE F; checks the exact integer identity (5); exhaustively checks selectors; constructs a TRUE three-branch case with branch 2 replaced by an actually satisfiable G and tests multiple distinct ORIGINAL witness extensions recovering the same bits; checks full ciphertext mask-shift equality at finite q. It was run TWICE per k with byte-identical JSON outputs. An independently authored Node checker, published as `INDEPENDENT_CHECKER.js`, separately checks exact integer identities, guard gadgets and complete selector truth tables; **425 assertions per run, executed twice identically**.

| k | variables | actual clauses | nonzero alpha entries | D | Python assertions | valid TRUE extensions | bit recoveries | full ciphertext equalities |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 3 | 46 | 68 | 131 | 3 | 567 | 118 | 240 | 24 |
| 4 | 61 | 90 | 174 | 3 | 962 | 119 | 240 | 24 |
| 5 | 76 | 112 | 217 | 3 | 2509 | 117 | 240 | 24 |

These checks do NOT sample the entire massive uniform source matrix in production dimensions, nor test QPT hardness. Full **uncompressed** degree-three source row counts are 10,917,020 / 62,034,256 / 238,449,982; a nominal 256-bit by four-byte row capsule would consume ~10.41 / 59.16 / 227.40 GiB respectively. This is not a practical WKEM or verified 128-bit parameterization. `OUTPUTS.json` contains exact run outputs and local checker SHA-256. The independent source Git blob is verified against the executed local Git blob. No independent agents or external research used.

## Exact remaining proof equations / failure modes

- **Every adversarial FALSE ORIGINAL x**, not just publicly degree-certified FALSE: an efficient Setup/Build of source-opening correlations jointly with an actual QPT LWE challenge simulator for (x,vk,CK,C,context,aux,related capsules), without assuming SourceOpen or discovering arbitrary unsat refutations.
- **Hard TRUE**: derive from *arbitrary* QPT unauthorized recovered final K/accepted native forgery either a genuine ORIGINAL witness R(x,w)=1 or a separately justified QPT hardness break **without requiring the adversary to supply a pseudoexpectation, low-degree representation or other intermediate**. Selector closure excludes one known fake but does not solve the generic extraction equation.
- Malicious N-of-N one-honest preauthorization/erasure and graph cut, abort and pre-funding data availability, target-private openings, authenticated SYS/BTC header work/ChainLock/tag/reorg/window assumptions, and a conditional no-EC-key-path native SLH-like endpoint remain unproved. No Bitcoin VM/NP verifier/PCP/trace disputes and no deployment claims.

**Next useful iteration:** an ORIGINAL-witness-aware, challenge-compatible hard-TRUE release/extraction construction, not further selector-rank bookkeeping. Do not count repeated certified FALSE examples as progress toward general adversarial FALSE and TRUE security.
