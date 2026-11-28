# NIDR: noisy polynomial-ideal dual release (restricted constructive checkpoint)

Run NIDR-2026-11-01-T07, completed offline. Parent research: GOIL blob b77d79ce786dab5342bfee4a8c4dfb74cce5e0d3 and XNAR blob ecfc80caae744ee6aedcf94b4e7549084256fd2c, PR 1 head b4483b53ce5364e23ffcaa465c427a50b031c268. Status: a concrete, limited-family release and an independently proved statistical FALSE hiding component. NOT a generic NP PQ witness-KEM, not calibrated QPT-128 security, not ready for production, and no solved hard-TRUE recovery-to-ORIGINAL-witness reduction.

## Actual classical-PPT Build and public off-chain release

Take Boolean ORIGINAL verifier V_x(W) including full relation identity and actual claim/outpoint, intended challenge branch, SYS/BTC anchors and observation window, scope, native verification key and signing domains. Compile its Boolean constraints into multilinear polynomial coefficient rows G_x in the quotient F_q[z]/(z_i^2-z_i). For degree D, use M = sum_{j=0}^D binom(n,j) monomial features and eligible bounded-degree constraint multiples. Optional invertible public row mixing A_x=R G_x preserves the rowspace. This compiler sees no ORIGINAL witness and uses no source-opening oracle. Every valid ORIGINAL witness W supplies a Boolean trace z(W) and monomial evaluation vector v(W), with v_0=1, A_x v(W)=0 and ||v(W)||_1 <= M; distinct W need not share an intermediate trace.

For odd prime q, independent s uniform in F_q^r, independent e uniform in integer [-B,B]^M, g=(q-1)/2, publish the single-bit vector ciphertext:

    beta = A_x^T s + e + g*m*e_0 (mod q).

With q>4BM+2, OFF-CHAIN Lift runs the original verifier, forms v(W), and decodes v(W)^T beta = g*m + v(W)^T e. The bounded noise is <g/2, so ALL valid original witnesses obtain the same precommitted bit on every supported error sample. Independently XOR-share the actual native private signing core per related capsule, encrypt every share bit independently, and reassemble the SAME original canonical key; public native checking fields and permitted P-domain signed transcripts must remain authentic. The native Bitcoin endpoint is hypothetical and only verifies an ordinary native PQ signature, never an NP verifier.

## Exact FALSE simulator if degree-D refutation exists

If e_0 belongs to the rowspace of A_x, solve A_x^T delta=g*e_0 by public Gaussian elimination. For any two bit messages m,m', the secret translation s'=s+(m-m')delta makes Enc(m;s,e)=Enc(m';s',e) EXACTLY. Uniform s is translation invariant. Therefore all independently encrypted bit/capsule ciphertexts are perfectly independent of their secret plaintexts, also when conditioned on the genuine checking-key correlation and public messages/signatures that reveal no plaintext shares or encryption coins. Coherent QPT processing of identical classical distributions changes nothing.

A FALSE Boolean system with a degree-D polynomial-calculus certificate 1 = sum h_i*g_i mod Booleanity has e_0 in the rowspace and meets this criterion. The full degree-n multilinear function space gives this for every FALSE instance but has exponential dimension 2^n. Promoting exact degree-bounded refutations to arbitrary NP at polynomial size would allow polynomial-time SAT decisions by rowspace elimination; DO NOT assume that.

## New approximate FALSE statistical simulator without exact refutation

Suppose there exists delta such that h=center_q(g*e_0+A_x^T delta) has integer L1 norm H. The exact coupling

    Enc(1;s,e) = Enc(0;s-delta,e+h)

holds modulo q. Shifting uniform s has no statistical cost. For each independent uniform error coordinate, the TV distance between e_i and e_i+h_i is at most |h_i|/(2B+1), so

    TV(Enc(0),Enc(1)) <= min(1,H/(2B+1)).

For T independent ciphertexts the full *classical public ciphertext* distribution is within T*H/(2B+1), uniformly over the genuine native checking key, independent public context, allowed signature transcripts, and independent related capsule shares. With actual native QPT-EUF-CMA against classical signing queries, an unauthorized fresh challenge-path signature then yields a separate native forgery under those restricted conditions. Secret-correlated auxiliary leakage, commitments to private shares, leaked protected encryption coins and arbitrary selective openings are EXCLUDED. This is statistical coupling, NOT an ordinary structured-A QPT-LWE reduction, and not generic FALSE security.

## Exact instantiated ORIGINAL family (parity cycles)

For n Boolean bits on a cycle, the ORIGINAL constraints are z_i+z_(i+1)-2*z_i*z_(i+1)-1=0. A degree-2 basis needs only M=1+n+n(n-1)/2 coordinates. For even n, exactly two distinct alternating Boolean ORIGINAL witnesses exist, both recovering the SAME key. For odd n>=3, the original statement is FALSE. Yet choosing delta_i=(q+1)/2 on every edge gives exact small shift:

    h_constant=-(n+1)/2,
    h_vertex_i=+1 for each of n vertices,
    h_edge_(i,i+1)=-1 for each of n edges,
    h_elsewhere=0.

Thus H=(5n+1)/2, and FALSE ciphertext bit distributions have TV distance <= (5n+1)/(2(2B+1)). For T independently encrypted share bits, choose B >= T*(5n+1)*2^lambda and suitable odd prime q>4BM+2; the union bound is <=2^-lambda, with polynomial bitlength, classical PPT sampling and O(n^2) ciphertext vector size. For the concrete q=2147483647,B=65536 fixture, n=3,5,7 give shift norms 8,13,18. This is a limited-family theorem: cycle satisfiability is EASY. It is not an NP-hard TRUE family and cannot be extrapolated into a generic statistical WE. A generic polynomial statistical construction for all NP would yield a statistical-distance characterization of NP satisfiability, with major unproved complexity consequences.

## Executed evidence, access model, unfinished work

The exact standalone standard JavaScript checker (checker.js) was run twice identically in a bounded V8 execution: 977 checks, including full q=7 exhaustive 2401-sample identical FALSE ciphertext-orbit comparison, n=3,5,7 FALSE shift/coupling, n=4,6 TRUE distinct witness recovery. Separate offline Python checkers passed 10,609 and 5,588 finite checks, each twice with byte-identical output; their longer derivation and provenance remain in the local downloadable archive. Tests are finite algebra only, not native SLH/Bitcoin, QPT LWE hardness, or native signing-oracle security.

The exact remaining generic equation is classical PPT Comp(R_original,x,scope,vk) and public Lift(C,W)=K_precommitted for EVERY valid ORIGINAL W, with arbitrary nonuniform-QPT FULL-public FALSE secrecy for all x (including no low-degree refutation or small shift) and arbitrary unauthorized hard-TRUE recovered key/native forgery -> an ACTUAL ORIGINAL witness or independent standard PQ break. Need a genuine jointly instantiated structured-source QPT challenge simulator and malformed/malicious setup, abort, coin disclosure and related capsule composition; do not assume an oracle, attacker-volunteered representation or standard uniform-A LWE. N-of-N preauthorization/erasure, watcher DA, SYS/BTC evidence, and hypothetical native Bitcoin PQ signatures remain separate. No web or external literature research, no independent agents, no production/main/workflow changes.