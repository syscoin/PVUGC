# SAI111 — noncommutative branching-program source gate pre-screen (NONQUALIFYING)

## Continuity and selection
Read live open/draft syscoin/PVUGC#1 branch research/pq-wkem-validation-20260918 at 77eb9b2ff6aae4af4504646dc96defb2fd6c6049 (SAI110, tree be372895cec39a685bc4c5992beb84cd0c140ea1). Read exact SAI110 note, blob 1f0f67a2ae77155a8fde55d6a2d8d6e901ca30e7. Scoped PR issue comments since 2026-11-18T19:20:00Z returned []. No Core source reread or FE implementation. This is a local gate-family pre-screen, not a new cryptographic advance.

SAI110's missing operation was PublicProject(C,w)=one frozen setup token for EVERY ORIGINAL qualifying future witness. A different attempted mechanism would avoid additive coefficient/abelian tensor covers: encode the GLOBAL original-source verifier as a noncommutative width-bounded branching program, hide its intermediate frames by random left/right masks, and release a fixed pad from a designated accepting group endpoint. This is a materially different *algebraic syntax*, but cannot be selected for implementation if its publicly exposed occurrence controls permit inconsistent paths. We screened that specific nearest regression before scaling to SHA/AuxPoW.

## Exact construction family
For a Boolean branching program of length L over a noncommutative group G, let U_j^b in G encode occurrence j's selected bit. The setup chooses random frames R_0,...,R_L and publicly serializes both transitions for each occurrence:

    M_j^b = R_(j-1)^(-1) U_j^b R_j.

The product of a public selection path b_1,...,b_L telescopes:

    Prod_j M_j^(b_j) = R_0^(-1) [Prod_j U_j^(b_j)] R_L.

A builder attempts to make ALL globally consistent satisfying witness inputs produce a designated endpoint g != identity and define K = H(domain||R_0^-1 g R_L), D=sigma_cancel XOR K. An honest Open(C,w) picks b_j=w[var(j)] and computes D XOR H(Prod_j M_j^(b_j)). If every globally consistent FALSE assignment produced only identity, the prescribed Open would reject.

## Explicit different-occurrence attack, screened before source compilation
The predicate f(x)=(x=0) AND (x=1) is identically FALSE but has two occurrences of one global variable. Let a=(0 1 2), b=(0 1 3) in S5, noncommuting 3-cycles; encode its two literals by

    A(x)=a if x=0 else identity,
    B(x)=b if x=1 else identity,
    P(x)=A(x) B(x) A(x)^(-1) B(x)^(-1).

For each actual global x=0,1, at least one A or B is identity, hence P(x)=identity. But the public package offers transitions independently by occurrence. A public adversary chooses x_first=0 and x_second=1, obtains

    [a,b] = (0 1)(2 3) != identity.

The masking frames cancel under this *inconsistent* selection exactly as under any honest path. If builder's accepting endpoint is g=[a,b], then the public adversary reconstructs R_0^-1 g R_L and therefore K, despite the FALSE global predicate. This does NOT require an abelian balanced cover, discrete logarithms, hidden-coefficient extraction, or an ORIGINAL source witness. It applies only to the exposed-transition BP construction, not to all possible noncommutative obfuscation or hash-only FE.

The script checks S5 permutation composition and both consistent paths versus the inconsistent selection. It did not construct random R_j, because the telescoping identity follows by cancellation for every R_j; no stochastic sample would improve that proof. Executed once using python3; the output is included verbatim.

## Why this is not a repair
Replacing occurrence controls by one global per-variable bit choice in prescribed Open is not a cryptographic enforcement: a public attacker still holds both M_j^0 and M_j^1 and can select each separately. Public labels for either bit make the same bypass possible. A hidden label-distribution gadget that yields only globally consistent labels to actual future original witnesses would itself need the missing noninteractive source-dependent gate. Adding a public SHA/PoW VerifyOriginal after constructing the accepting endpoint does not stop the public extraction.

Consequently this family was rejected at source-coupling screening without scaling it into a long synthetic circuit, another tensor variant, or source-independent PRF table. R366's finite-cover regression remains relevant but is not claimed as identical to this simpler mixed-occurrence path. No genuine Build_inc/Open_inc for original strict-PQ source histories, no FALSE/hard-TRUE joint QPT security, no signed cancellation transaction, and no malicious-setup reduction was produced.

## Next exact equation
Need an actual polynomial-time, hash-only public program/encoding whose source input is one globally authenticated ORIGINAL certificate, not arbitrarily combined local choices:

    Build_inc(x_W,sigma_i) -> C_i;
    Open_inc(C_i,w)=sigma_i for every R_original(x_W,w)=1,

with a complete-public QPT recovery/accepted native forgery -> an actual ORIGINAL qualifying source certificate or independent justified hash/native break. Preserve the three OR branches and full claim/anchor/work/LC-depth/strict-contextual AuxPoW/capsule/endpoint binding. One-honest N-of-N setup and BTC native signing remain separately conditional.

**NONQUALIFYING screening only.** No progress comment, notification, deploy, production edit, or automation mutation.
