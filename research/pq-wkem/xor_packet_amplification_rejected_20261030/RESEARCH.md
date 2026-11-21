# XOR-packet amplification of ORIGINAL-to-LWE release — exact rejection

**Status: NO POSITIVE PQ WITNESS-KEM CONSTRUCTION ADVANCE.** This is one bounded, offline repair attempt, not a secure SOURCE, native PQ signature or Bitcoin deployment.

## Provenance and exact predecessor

Research record \`xor_packet_amplification_rejected_20261030\`, automation turn 10; no separately supplied execution UUID. Existing open/draft/unmerged syscoin/PVUGC#1, branch \`research/pq-wkem-validation-20260918\`; original observed head \`a1fd891991b9f8b0b00a2a3ce0413e4d6ac40ba2\`. Latest substantive ordinary comment available was 6521064731. Exact predecessor \`research/pq-wkem/signed_unit_repetition_no_go_20261030/RESEARCH.md\`, blob \`5e46166daac64ef44bd2485a1b63f8f3272ffffe\`, and latest independent-source \`slotwise_last_sources_20261030/RESEARCH.md\`, blob \`84c0054be9020d5bd04b7d5360ce1e7865e2ca56\`, were read. No external literature, web search, entire PR diff or archive replay. The selected repair is DIFFERENT from replicating constraint rows: split each native-secret bit into many independent encrypted XOR shares, hoping one invalid pseudo-opening error will spoil the entire secret.

## Candidate: explicit release and correctness for every ORIGINAL witness

Compile a Boolean verification circuit into integer \`C v=t\` with Boolean slack variables. For an AND gate \`c=a AND b\`, introduce Boolean \`s1,s2,s3\` and equations
\`\`\`
a-c-s1=0; b-c-s2=0; a+b-c+s3=1.
\`\`\`
Set \`A=C\` and \`U=2t-C 1\` over an odd prime field. Every satisfying ORIGINAL witness W supplies a signed vector \`z(W)=2v(W)-1\` with entries ±1 and \`A z(W)=U\`. For the unconstrained-input TRUE AND relation all four valid assignments yield distinct source vectors. No canonical/common witness state is required.

Let K be the one precommitted complete native signing capability, with its genuine native checking key pk and bound relation/claim/UTXO/branch/anchors/window/context/challenge path. For each of its L bits, choose T Boolean XOR shares, the first T−1 uniformly and the last fixed by K. For each share and each related capsule independently sample \`r<-F_q^n\` and \`eta,eta_d<-Uniform({-1,0,1})^(m+1)\`, then publish
\`\`\`
c = A^T r + eta                 (mod q)
d = U^T r + eta_d + g*(3+share) (mod q)
g = 2*(m+1)+1; q is prime >32g.
\`\`\`
For valid W, \`d-z(W)^T c = g*(3+share)+eta_d-z(W)^T eta\`; the centered error is always at most \`m+1<g/2\`. Nearest-center decoding over \`{0,g,...,7g}\` returns exactly \`3+share\` for EVERY valid ORIGINAL W, for every honest bounded error draw and every independently randomized same-scope capsule. XOR of shares gives the SAME actual K; native \`PK(K)=pk\` must be checked. The checker uses a SHA-256 key-link **mock**, not native post-quantum signature functionality.

## Exact fixed-FALSE full-public attack and failed amplification

Fix ORIGINAL \`a=0,b=1,c=1,c=a AND b\`. There is **no accepted signed-unit SOURCE opening**: the first gate forces \`z_s1=-3\`. Nevertheless the publicly computable INVALID integer vector
\`\`\`
z_bad=(-1,+1,+1,-3,-1,+1,-1,...,-1)
\`\`\`
satisfies every public equation \`A z_bad=U\` (including added fixed-zero dummy variables). It is NOT an ORIGINAL witness or accepted SOURCE opening. The adversary ignores the software validity check and directly evaluates \`d-z_bad^T c\` on each public packet. The resulting noise \`E=eta_d-z_bad^T eta\` contains exactly one independent coefficient of magnitude 3 and m coefficients of magnitude 1. Its absolute maximum is m+3, and incorrect decoding of interior digit 3 or 4 occurs exactly when \`|E|>=m+2\`, since \`g/2=m+1.5\`.

For \`|E|>=m+2\`, the magnitude-3 term MUST take its aligned extreme and all m unit terms must align, except possibly one zero. There are exactly \`2*(m+1)\` such assignments among \`3^(m+1)\`. Thus the **exact**, classically checkable failure probability per packet is
\`\`\`
p_m = 2*(m+1)/3^(m+1).
\`\`\`
Across independent L*T packets, when every pseudo-decoding is correct the adversary reconstructs the REAL secret K and can use/check it against the genuine pk. Consequently, even allowing all public context, checking keys and related capsules,
\`\`\`
Pr[unauthorized complete K recovery on this fixed FALSE x]
  >= (1-p_m)^(L*T) >= 1 - L*T*p_m.
\`\`\`
Other key-guessing strategies and related capsules may improve the attack; this is only a conservative LOWER bound. If L and T are polynomial in m, the lower bound tends to one. This is a direct classical PPT attack, hence also defeats arbitrary-QPT security for this proposed compiler regardless of ordinary-LWE hardness of a DIFFERENT, uniform-matrix distribution.

For an L=256-bit K, a NECESSARY, NOT SUFFICIENT, condition for driving merely this lower bound below 2^-128 is
\`T>=ceil(128*ln(2)/(256*(-ln(1-p_m))))\` packets PER secret bit. The exact executed checker reports: m=6 needs ≥54; m=12 ≥21,252; m=20 ≥86,316,242; m=32 ≥29,191,266,350,530; and m=64 ≥2.7e28. This exponential cost rules out the suggested polynomial-packet repair as a general solution.

## Attempted repair of noise isolation, and its separate failure

Concentrating each packet's noise on one randomly selected coordinate would reveal the invalid coefficient −3 in O(m) trials instead of exponential trials. But one-sparse noise destroys ordinary-LWE hiding: if the first n columns of A form an invertible submatrix, with probability 1−n/m their errors vanish, so r is recovered directly by solving these n public equations. If an error is in the prefix, enumerate the 1+2n possible prefix noise patterns and check that the whole residual has Hamming weight ≤1 and values ±1. The local extended checker recovers the full encryption secret r and bit without any SOURCE witness in every 24 invertible-prefix index/sign trials. This argument does not claim to rule out all correlated-noise schemes.

## Executed evidence and precise remaining obligation

The exact committed standalone \`check.js\` was executed under Node twice with byte-identical \`OUTPUT.json\`, **52 assertions per execution**, checking all four TRUE Boolean AND witnesses, the fixed FALSE pseudo-opening across m=6,12,20,32,64, the exact integer-convolution noise law, all 3^7 noise vectors for both interior encoded bit centers, and required packet counts. A distinct longer LOCAL-ONLY Python checker passed **14,001 assertions twice identically**; it also recovered the SAME 256-bit mock secret from false-source pseudo-openings in TWO independently randomized related capsules and exercised the sparse-error break. Exact local SHA-256 of compact checker: \`ecada13644c8ad3f6a4ee1d02ce8f6138ad39e8bb6855b872aba9f96f81329a8\`; captured compact output: \`2dccca492581c9279cd0b4d4a10fe88eadbd587d224ef991dc903ac86649786b\`. Toy/seeded tests are not QPT-hardness evidence or a native signature/Bitcoin implementation.

**Next exact missing construction:** independently instantiate a witness-free classical-PPT relation-dependent \`Comp(R_original,x,claim/UTXO,branch,anchors/window,context,pk)\` and public \`Release(D,W)\` that give the SAME precommitted native capability for every valid ORIGINAL witness, while an arbitrary QPT algorithm cannot obtain that capability for every fixed FALSE x from the FULL joint view (capsule, relation, checking key, auxiliary data, related capsules and malicious setup), including any nonaccepted pseudo-opening. Unauthorized hard-TRUE final-key recovery or accepted native forgery must reduce to an actual ORIGINAL W or independent justified QPT break; a supplied representation is not enough. Source-dependent setup/opening data and QPT challenge simulation must be jointly instantiated, not patched from marginal ordinary LWE hiding. One-honest N-of-N graph/abort, SYS/BTC qualification and the hypothetical native PQ Bitcoin endpoint also remain unproved. No merge, production change, deployment or automation completion is justified.
