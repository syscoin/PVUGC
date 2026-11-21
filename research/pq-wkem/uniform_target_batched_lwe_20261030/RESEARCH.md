# Uniform-target batched dual-LWE SOURCE: no planted opening (restricted result)

**Status.** A concrete classical-PPT SOURCE sampler/encryption/release construction and straight-line QPT-LWE hybrid have been instantiated together. Every valid signed-short SOURCE preimage tuple opens the **same genuine precommitted native key**. Unlike the predecessor, honest setup generates no SOURCE preimage and cannot retain a planted one. This **does NOT** give a generic-ORIGINAL-NP witness-KEM, a malicious complete N-of-N graph, all-fixed-FALSE SOURCE security, or a supported Bitcoin endpoint. It is a restricted hard-TRUE SOURCE component, not a completed release system.

## Provenance and exact unfinished step

Run \`uniform_target_batched_lwe_20261030\`; authorized \`syscoin/PVUGC\` draft/unmerged PR #1, branch \`research/pq-wkem-validation-20260918\`; read starting SHA \`b5c58d9ca5247b4806b03264be23b383a6ec14d7\`, predecessor \`research/pq-wkem/source_separated_one_honest_20261030/RESEARCH_AND_CHECKER.md\` blob \`e64d177b4084f05b9ff791f224d54782d5d0c70c\`, ordinary comment \`6515338192\`. No internet/literature search or full PR diff. The selected gap was the honest participant's *planted* LWE SOURCE witness and an incomplete joint challenge simulator, while preserving independently generated source/signing slots for one-honest early safety.

A local attempt to use ORIGINAL 3-coloring's *linearized* SIS opening was rejected: a signed integral pseudo-solution decrypts K4's FALSE graph despite no genuine coloring. The surviving algorithm below is a **uniform-target sampled SOURCE**, not a compiler from 3COL or arbitrary NP.

## Explicit classical algorithms and exact distributions

Let q be odd prime; n,m,w,L,J polynomial; B>0; chi a specified efficiently sampleable integer error distribution supported in [-B,B]; ell bits/digit; g=floor(q/2^ell), with **g>2B(w+1)**. Let T be exactly the signed constant-weight set

\[
T=\{z\in\{-1,0,1\}^m:\|z\|_0=w\},\quad |T|={m\choose w}2^w.
\]

Choose the *real native* signature key pair \`(sk*,pk*)<-Native.KeyGen\`. Set \`L=ceil(serialized_secret_bits/ell)\`; require exact canonical serialization and zero top padding. The setup/capsule attestation binds \`(original relation identity,x,claim/UTXO,branch,anchors/window,challenge path,authorization mode,pk*,source,all related capsule IDs)\` and may use only genuine SETUP-domain signatures, never protected challenge-path signatures.

**SetupSource:** sample independent, uniformly random \`A<-F_q^{n x m}\` and \`U<-F_q^{n x L}\`. Publish \`M=[A | U]\`. This honest algorithm does **not** sample or search for ANY short preimage and holds no SOURCE trapdoor; it has only temporary matrix-sampling coins. Erase/protect native signing secrets and encryption coins after valid pre-funding checks. No one must remain online for the mathematical Release.

**Enc(M,sk*,j):** with complete native-secret digits \`a_l in [0,2^ell-1]\`, sample independent uniform \`r_j<-F_q^n\`, \`eta_j<-chi^{m+L}\` for each permitted related capsule j, and publish one vector of length m+L:

\[
c_j=A^\top r_j+\eta_{j,1:m},\qquad
d_{j,l}=U_l^\top r_j+\eta_{j,m+l}+g\,a_l\pmod q.
\]

**SOURCE witness relation:** \`R_SRC(M,Z)\` accepts a tuple \`Z=(z_1,...,z_L)\` iff each \`z_l in T\` and \`A z_l=U_l (mod q)\`. The z_l may be different for each digit and completely different between valid witness tuples; no common short preimage is assumed.

**Public off-chain SOURCE Release:** compute for every l

\[
d_{j,l}-z_l^\top c_j=g\,a_l+\eta_{j,m+l}-z_l^\top\eta_{j,1:m}\pmod q.
\]

Each centered error is at most \`B(w+1)\` **for all valid Z and all bounded sampled errors**. The 2^ell circular centers are spaced by at least g, including wrap-around; strict \`g>2B(w+1)\` gives deterministic unique nearest-center decoding of the entire same \`sk*\` from EVERY valid Z and each fresh capsule. Reject noncanonical native secret serialization or \`PK(sk)!=pk*\`. The resulting actual native signature is made *off-chain*; Bitcoin is not asked to run NP verification/VM/PCP/BitVM disputes. A hypothetical no-EC-key-path PQ-native signature endpoint is conditional and not deployed.

## No planted opening, and source-availability theorem

For a fixed target column l, let \`X_l=|{z in T:Az=U_l}|\` and \`mu=|T|/q^n\`. Uniform independent A,U make each indicator occur with probability q^-n. For distinct z,z', \`z-z'\` is nonzero mod odd q, hence

\[
\Pr[Az=U_l\;\land\;Az'=U_l]
=\Pr[A(z-z')=0]\Pr[U_l=Az\mid A]
=q^{-2n}.
\]

So \`E[X_l]=mu\`, \`Var[X_l]=mu(1-q^{-n})\`, and Chebyshev plus a union bound, **without assuming U targets independent after conditioning on A**, gives

\[
\Pr[\exists l:\;X_l=0]<Lq^n/|T|.
\]

This is genuine high-probability **existence** with no witness known by setup, NOT an efficient SOURCE-opening algorithm and NOT ORIGINAL fork-evidence correctness. The exhaustive toy enumeration in the checker is test-only and is *never* part of honest Setup.

## Full-public QPT hybrid with actual checking key, related capsules, corrupt participants

Independently assume nonuniform QPT decisional LWE for the **EXACT** distribution

\[
(M,M^\top r+\eta)\ \stackrel{c}{\approx}_{QPT}\ (M,U'),\quad
M\leftarrow F_q^{n\times(m+L)},\ r\leftarrow F_q^n,\ \eta\leftarrow\chi^{m+L},\ U'\leftarrow F_q^{m+L}.
\]

Also assume actual native EUF-CMA security against QPT adversaries making only classical nonchallenge signing queries. These assumptions are *not* proven here or calibrated to 128-bit concrete security. The adversary may have nonuniform quantum advice independent of fresh honest SOURCE/key/coins; perform coherent QPT computation on the complete classical public relation/x/context, genuine pk, native setup authentications, all individual and same-scope related capsules; adaptively choose N-1 corrupted participants' malicious SOURCES, keys and disclosures (even public \`U_i=0\`) after observing the honest public data, and retain all their sources/coins/witnesses. The SAME h must stay honest for all J capsules. Honest LWE coins/preimages and native sk are never leaked. No source-decryption oracle, superposition signing/coin-opening queries, witness-correlated arbitrary quantum advice, or unauthorized new native target signing is allowed. Auxiliary records must be efficiently simulatable from the challenge public view, not secretly depend on the challenge r/eta or sk.

Fix one h. G0 is honest M_h, native pk_h and real shifted LWE ciphertexts. In G0→GJ replace **one whole \`m+L\`-coordinate capsule at a time** by a uniform vector. A standard decisional-LWE challenger provides exactly the shared uniform M_h and one real-or-uniform vector; a reduction that knows sk_h shifts its last L coordinates by the **entire native secret digits**, generates all other capsules honestly from M_h, and signs exact full setup records with the real sk_h. Any adaptive malicious members and auxiliary data are postprocessing of this joint view. This is a straight-line **QPT** reduction, retaining quantum memory with no SourceOpen oracle or quantum rewinding; cost at most \`J Adv_QPT-DecLWE\` (not J*L). In GJ all ciphertexts are uniform independent of sk_h: embed the **genuine** native EUF-CMA pk_h and obtain allowed classical SETUP-domain signatures from the real oracle. A fresh unauthorized h native signature, or recovered usable sk_h which signs a fresh target, is a native EUF-CMA forgery. Thus, for fixed survivor h and authorized setup transcript constraints,

\[
\Pr[\mathrm{unauthorized\ h\ native\ signature/key}]
\le J\,\mathrm{Adv}_{QPT-DecLWE}(n,m+L,q,\chi)
  +\mathrm{Adv}_{QPT-Native-EUF-CMA}
  +\mathrm{Adv}_{\mathrm{aux\ authenticator\ forgery}}.
\]

An unknown honest position costs an explicit at-most-N guessing/union loss. This is for an **ABSTRACT** native N-of-N gate from the previous restricted construction, not an established Bitcoin multi-SLH script or a usable funded transaction graph. Multiple capsules may only reuse the same native key in the same authenticated claim/path scope and have fresh full LWE r/eta. Adversarial source openings for corrupt slots cannot open the independently uniform honest M_h.

As an additional check on the hardness interface: a QPT algorithm obtaining any short z_l from a fresh uniformly sampled M *before seeing an LWE ciphertext* can test the LWE-vs-uniform challenger vector by evaluating its last-coordinate minus z_l times its base coordinates. Real LWE yields bounded error, uniform yields uniform residue, giving a straight-line decisional-LWE distinguisher. This does **not** imply an arbitrary final-key attacker must output a source representation.

## CRITICAL unresolved boundaries

**(A) ORIGINAL witness is NOT an ISIS opening.** There is NO instantiated classical-PPT \`Comp(R_original,x,claim/context,pk*)\` and \`Lift(x,W,M_x)=(z_1,...,z_L)\` enabling every valid ORIGINAL fork witness W to open this precommitted native key. Simply grafting W onto an independently uniform M is impossible under the preceding LWE assumption when a publicly known valid (x,W) is available, since an efficient Lift on uniform M itself gives the above LWE distinguisher. A successful future source must encode ORIGINAL relation-sensitive correlations and provide an exact joint-public simulator for them, or change primitives. This is the **next exact equation**, not a missing SourceOpen oracle.

**(B) NOT every fixed FALSE SOURCE is hidden.** For A=I_2, U=0, relation restricted to exact signed weight w=1, there is no valid source witness, but d_l=eta_last+g a_l visibly leaks the message. The LWE game requires uniformly sampled M. For a fixed FALSE **ORIGINAL** x with an independent uniform M, the restricted LWE hybrid still hides the key against permitted auxiliary distributions; this cannot establish a useful generic ORIGINAL release.

**(C) Setup/endpoint incomplete.** There is no malicious unknown-one-honest N-of-N *fundable graph*, graph-bypass proof, pre-signature/DA completion, publicly checkable correct release of corrupt slots, usable abort completeness, original SYS/BTC fork qualification, censorship/reorg handling, or deployed native PQ Bitcoin capability. The previous source-separated component's abstract N native signatures remain an abstract restriction. No trusted last verifier/online committee has been introduced; the honest-erasure baseline is distinct from an optional stronger keyless builder.

## Exact bounded checks and illustrative resources

\`check.py\` (SHA-256 \`dad404717d0e86068395d3763451612582cecbc99fc2d1994b7893b89b005f10\`) was executed twice with byte-identical \`OUTPUT.json\`, 58 assertions. Exact enumeration of all 625 F5 one-target matrices/targets validates first moment 2.4, variance 1.92 and absence count 84. A fresh UNPLANTED uniform toy A,U with 86 independent target columns has 5–20 distinct signed source preimages per column (located by TEST-ONLY enumeration), and eight different complete tuples each release the SAME 256-bit mock capability in two independently randomized capsules. The checker verifies cross-source known-opening nontransfer and the FIXED FALSE SOURCE failure explicitly. The SHA-256(pk) link and seeded sampling are functional mocks, not native PQ signatures or QPT experiments.

Uncalibrated example: q=16777213 (checker trial-division prime), n=256,m=6800,w=2000,B=128,ell=5, serialized native secret 256 bits, L=52,J arbitrary polynomial. Then g=524287, noise bound=256128, \`log2 mu=1792.513736\`, \`log2 Pr[one of L targets lacks a preimage] < -1786.813296\`. At 3 bytes per field element, M is **5,262,336 bytes** and one batched native-secret ciphertext is **20,556 bytes**, versus 1,060,956 bytes for L separate full dual-LWE ciphertext vectors (51.6x smaller). The matrix-vector product takes roughly 1.75 million modular multiply-adds per capsule, NOT benchmarked. Four independent honest-source slots quadruple source storage. Concrete 128-bit LWE/PQ-native security remains UNVALIDATED.

**Handoff.** Preserve this uniform-target dual-LWE as a source-only candidate with a real QPT proof opportunity and no planted opening. Next: a genuinely instantiated ORIGINAL relation-conditioned compiler and full-public LWE simulator together, such that every valid ORIGINAL W computes potentially distinct source states and gets the same sk*, with FALSE-original and unauthorized-hard-TRUE security in the joint public view. Do not mistake source availability, SOURCE short preimages, native checking keys or setup attestation for the missing ORIGINAL witness reduction.
