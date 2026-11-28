# Run 570 — low-output directed-seam injectivization and exact XOR-Sidon bound

2026-10-16, one bounded research-only falsification; live starting PR #1 branch research/pq-wkem-validation-20260918 at cb9d042d6daeb41a09f955083f7c078867708d55 (draft/open/unmerged). This corrects Run 569's apparent need for a wide public function output. Output truncation to **one bit** is not a defense if all three correlated public seam functions remain coherently accessible. The injectivization principle is **Gharibi 2012**, not a newly invented quantum algorithm. The XOR-Sidon refinement below specializes that result to the actual directed-seam toy interface.

## Model and scope

In an ideal-oracle experiment honest classical PPT setup samples a nonzero Delta in {0,1}^n and independently uniformly random public functions A,B:{0,1}^n -> {0,1}^b. It exposes an opaque deterministic public seam oracle F(s)=A(s) XOR B(s XOR Delta). Every public program and public checking key, all other capsules/statements, and arbitrary quantum auxiliary state are in the adversary view. An arbitrary QPT adversary may query **A, B and F coherently**. No concrete classical-PPT implementation of an ideal random-function oracle or of the opaque F program is claimed, and no malicious constructor is needed. The result does **not** apply automatically to CCMR or CLZ unless their actual exposed programs permit this precise oracle interface.

The left-cancelled public oracle is G(s)=F(s) XOR A(s)=B(s XOR Delta). At b=1, B itself is very far from injective, so Run 569's direct Simon-promise proof does not apply. Nevertheless the adversary may use public selected offsets T={t_1,...,t_k} and form V_T(s)=(B(s XOR t_i))_i. Define J_T(s,z)=V_T(s) for z=0 and J_T(s,z)=(G(s XOR t_i))_i=V_T(s XOR Delta) for z=1. It always has period p=(Delta,1). If V_T is injective, J_T is **strictly two-to-one**, and Simon's algorithm recovers Delta with n+kappa' quantum samples except with probability <=2^-kappa'. Each quantum sample needs O(k) coherent A/B/F queries and polynomial reversible postprocessing, giving O(k(n+kappa')) base queries. Classical measurements do not imply this bound.

## Exact pair-collision probability

For any s!=s' with d=s XOR s' and any distinct T, set c_d equal to the number of unordered pairs {t,t'} subset T with t XOR t'=d. Translation by d is an involution. Of the k equalities B(s XOR t)=B(s' XOR t), each pair of offset partners duplicates one equality. The remaining k-c_d equations involve disjoint pairs of independent uniformly random B outputs. Exactly:

Pr_B[V_T(s)=V_T(s')] = 2^(-b(k-c_d)).

Always c_d <= floor(k/2), recovering Gharibi's generic injectivization bound 2^(-b ceil(k/2)). In the XOR setting we can construct public offsets with c_d <= 1 for every d!=0. This yields the sharper union bound

Pr_B[V_T not injective] < 2^(2n-1-b(k-1)).

### Explicit polynomially computable offsets

For even n=2h, identify n bits with GF(2^h) x GF(2^h) and use k distinct points from the cubic graph T_full={(a,a^3):a in GF(2^h)}. Given a nonzero XOR difference (d,e), two distinct points a and a+d have second-coordinate difference d*a^2+d^2*a+d^3=e. Dividing by d^3 gives z^2+z=constant. It has at most two roots differing by one; those roots describe the **same unordered pair**. If the first-coordinate difference is zero no two distinct graph points match. Thus all unordered nonzero differences are unique (the classical APN/Sidon property). No claim is made that this field construction is newly invented.

For k <= 2^(n/2), choose k=ceil((2n+kappa)/b)+1. Injectivization fails with probability <2^(-kappa-1), and the combined ideal-oracle quantum attack succeeds with probability >=1-2^(-kappa-1)-2^(-kappa'). For n=128, b=1, kappa=kappa'=128, **k=385** publicly known offsets suffice. Simon then needs 256 grouped samples, or O(385*256) coherent base-oracle calls up to constant factors. This is a query bound, **not** an estimate of physical quantum gates or resources.

## Falsification and mandatory attack-family scope

(1) Seam: public A algebraically cancels. (2) Global synchronization: recover Delta. (3) Statistical fingerprint: individual (A,F) and (B,F) views remain Delta-independent in the ideal model; their joint view does not. (4) Multi-view/capsules: a single exposed triple suffices; reuse exacerbates correlation. (5) Chosen-input: the attack concatenates k coherent evaluations, not a classical exhaustive search. (6) Malicious setup or retained coins: unnecessary for the honest random-oracle attack; retaining Delta is independently fatal to a Delta-only release. (7) Cross-UTXO/branch reuse: KDF domain separation does not conceal recovered Delta. (8) Public verification key: correlated key data is in the view but unnecessary to recover Delta. (9) Quantum: Simon with an injectivized shifted oracle, not Grover.

**Actual consequence:** If the entire hidden ingredient of a protected capability is Delta and K_x=KDF(context_x,Delta), the attacker obtains K_x without an ORIGINAL witness. Recovering Delta does not imply recovery if the capability also depends on independent hidden material. If the actual program hides A or B from separate coherent access, or B is nonrandom/structured, this probability analysis does not establish an attack. There is no relation-dependent source-authenticated release implementation here.

Run 259 remains a downstream theorem **only for supplied complete accepted representations z** whose zero residual extracts an ORIGINAL witness, or whose invalid compressed acceptance gives the specified QPT SIS solution. Delta and a bare native signature are not z. Run 567 separately warns that SIS-compressed satisfiability can differ from ORIGINAL satisfiability. All-witness SAME-capability correctness in a concrete system, full-public false-instance QPT hiding, unauthorized true-instance recovery/forgery -> ORIGINAL or an independent QPT break, N-of-N malicious setup/abort/erasure, multi-capsule security, concrete post-quantum resources and the conditional P2MR/native SLH Bitcoin branch remain UNPROVED.

## Reproduction and literature

The exact executed pure-ECMAScript checker and captured JSON are published alongside this note. It exhaustively verifies 2,949,120 Boolean-function assignments across 45 exact pair-collision cases on a 4-bit domain, four finite cubic Sidon offset families, and six n=10, b=1 three-view fixtures with 32 offsets, genuine strict two-element fibers and GF(2) recovery from simulated Simon samples. No quantum hardware, cryptographic WE, or real mixer is implemented.

The **primary proof** for generic injectivization and Boolean-hidden-shift reduction is Mirmojtaba Gharibi, "Reduction from non-injective hidden shift problem to injective hidden shift problem", arXiv:1207.4537v2 (2012), Sec 2.1, Theorem 1, Corollaries 2–4, https://arxiv.org/pdf/1207.4537 (PDF pp. 3–5 visually inspected). Its method was already known. CCMR's TCC 2024 local-mixing paper https://doi.org/10.1007/978-3-031-78023-3_2 is architectural background, not a construction shown to expose this interface. Live exact prior inputs at starting head: Run 569 note blob 82b6f7eed36bb7a3bc4683f6cc3d11690135c4de; Run 259 note blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622.

**Handoff:** Do not rely on low-width public seam outputs for QPT security when the complete correlated public view enables shifted queries. For an actual minimally protected late-witness mixer, first specify and audit the exact coherent public-evaluation interface. No completed practical PQ WKEM is claimed. No production changes.
