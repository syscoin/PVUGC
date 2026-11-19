# R379 — whole-input SHA differential correction tree (NONQUALIFYING)

## Continuity and single candidate

Opened current syscoin/PVUGC PR #1 at branch research/pq-wkem-validation-20260918, head 349e97bdc602dc3597b4b3a4635192278eeb750d (R378, exact blob add9569ae51bfb73faefaf280359a25c0b670978). Latest ordinary comments since 2026-11-18T19:24Z: none. R378 proposed whole-input correlated XOR differences E_j(w)=F_(j-1)(w) XOR F_j(w) for accepted local gates, with F_m(w)=F_0(w) XOR K. Its naive SHA/GGM serialization exposed individual constituent masks, allowing FALSE cross-clause splice. This iteration explicitly changes the public representation to SHA-expanded PAIRWISE DIFFERENCES plus per-prefix differential corrections; it does not expose the private seeds.

All approved ORIGINAL three OR challenge grounds remain as supplied: strictly greater qualifying Bitcoin work, finite authenticated withdrawal-specific burn fault, or qualified strict-modern Syscoin inconsistency/tag fault with required LC depth. Same claim, window, source and native cancellation binding, no modified source relation. No Core source reread or network / Bitcoin admission test was performed this execution.

## Concrete finite-domain Build/Open attempt

For each full Boolean witness string w of n bits, choose three independent secret 256-bit GGM seeds s0,s1,s2 and expand each bit b using G_b(s)=SHA256("R379:SHA-DIFF:branch" || byte(b) || s). Write s_i(p) for the seed at prefix p and the last virtual endpoint F3(w)=s0(w) XOR K. Let

    d1(p)=s0(p) XOR s1(p)
    d2(p)=s1(p) XOR s2(p)
    d3(p)=s2(p) XOR s0(p).

Their XOR is zero at every prefix. Publish the three ROOT DIFFERENCES only. For each parent prefix p and next bit b, define the SHA differential correction:

    t_j(p,b)=d_j(pb) XOR G_b(d_j(p)).

Public update d_j(pb)=G_b(d_j(p)) XOR t_j(p,b) reconstructs a pairwise seed difference, not either constituent seed. For the terminal depth n ONLY, use d3(w) XOR K when forming t_3. At the terminal, publish t_j(p,b) only for words w=p||b with c_j(w)=1; publish all earlier-prefix corrections. Publish D=S XOR K. A fully satisfying w can compute all three terminal differences, XOR them to K, and open exactly S=D XOR K. Every fully satisfying word yields the same S.

The SHA expansion here is real SHA256, but the finite-domain implementation explicitly enumerates prefixes and accepted leaves. Its size is exponential, not a practical classical-PPT Build for a future SHA/AuxPoW witness. The unfiltered number of prefix corrections is 3*(2^(n+1)-2) for m=3; the internal corrections are 3*(2^n-2), plus up to 3*2^n terminal corrections. At n=4 the full tree has 90 slots and the FALSE gate fixture publishes 66. A Merkle root would only authenticate these records, not generate unseen per-witness corrections.

## Exact FALSE simulator only for an independent-leaf idealization

If each complete-input child mask is independently uniformly distributed, choose on each FALSE w a missing edge j(w). To replace S by S'=S XOR Delta and K by K'=K XOR Delta while preserving D and ALL published terminal edges, retain leaf s0(w) and change leaf s_i(w) by Delta for each i>=j(w), i in {1,2}. The endpoint s0(w) XOR K also changes by Delta. Each available edge has both endpoints changed or both fixed, hence is unchanged. The single changed edge at the boundary is not published. The transformation is a measure-preserving bijection on the uniform independent-leaf tape, preserving the complete ideal public correction table and D (including coherent reads of the classical table). This is exact FALSE hiding only for that abstract EXPONENTIALLY LABELED fresh-leaf distribution.

In actual SHA-GGM, each child seed is deterministically G_b(parent seed). Independently changing selected leaves is not a valid change of the underlying root tapes while holding their public prefix differences and corrections fixed. Thus the ideal tape coupling DOES NOT furnish a concrete full-public SHA capsule simulator. Quantum, hard-TRUE, correlated sibling, and malicious-setup security are all unproved. Full-public manipulation of the real deterministic correction bytes was not exhaustively analyzed.

## Why the obvious polynomial seed-difference update fails

A correction-free PUBLIC update U_b on root XOR differences would need

    G_b(a) XOR G_b(c)=U_b(a XOR c)       for ALL a,c.

Setting c=0 forces U_b(z)=G_b(z) XOR G_b(0), hence

    G_b(a XOR c)=G_b(a) XOR G_b(c) XOR G_b(0).

This forces G_b to be affine over F_2. Actual SHA expansion does not have the required difference homomorphism. Publishing SHA correction values t_j at every distinct prefix handles nonlinearity but is exponentially large. Publishing every terminal correction without checking c_j lets any word open K even on FALSE instances. Thus the missing operation is an EFFICIENT cryptographically gate-restricted correlated differential evaluator, not an external verifier bit, an exposed constituent seed, a root-only hash, or a renamed FE/WE assumption. This is a limitation of the attempted root-difference-only update syntax, NOT a general impossibility theorem for hash-only encryption.

Sharing distinct prefixes in a polynomial-width state machine would require a new sound global-consistency mechanism; naive state merging is subject to prior R376/R366 path-splice/finite-cover regressions. No such mechanism is supplied here.

## Executed bounded checker and handoff

An actual Python3 standard-library checker used a SHA256 differential tree over all 16 four-bit words, with 256-bit TEST seeds. FALSE fixture: c1=b0 XOR b1 XOR b2 equals 0; c2=b1 XOR b2 XOR b3 equals 0; c3=b0 XOR b3 equals 1 (jointly inconsistent). TRUE fixture substitutes c3=0. It checked the exact SHA correction/update equality, every TRUE witness returning one S, absence of a full prescribed three-edge path for every FALSE word, the explicitly restricted independent-leaf FALSE tape coupling, and one SHA nonhomomorphism control. Its output reports 16 FALSE words, four TRUE words, and 66 published FALSE corrections. These controls do NOT show cryptographic secrecy of SHA-derived corrections or source-based release.

Checker SHA256 275ac5800f0e86f871faf9fcb45d337210a66cffc949a113be22c735eafa83b0; output SHA256 76ca2a60ee92aefa9cfa8f84d0e2a883848a75af85ca251e61493b8d862a6b7b. Actual checker and output source are committed with this note, subject to byte-identical readback. Initial failed local invocations hit a Python undefined identifier and then an incorrect TRUE/FALSE fixture flag; only the corrected successful execution is cited.

No actual qualifying ORIGINAL Bitcoin/Syscoin source certificate, real FE, practical classical-PPT Build/Open, full-public FALSE or hard-TRUE QPT reduction, native forgery-to-evidence theorem, malice-secure N-of-N setup or timely source work theorem has been instantiated.

**NONQUALIFYING.** Next equation is the practical polynomial-sized PUBLIC source-gated correlated difference evaluator with a valid joint-public simulator, or abandon this exact differential-GGM route. No PR progress comment, user breakthrough notification, Core/production change, deployment or automation change.
