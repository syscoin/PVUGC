# SOURCE whole-public Fourier/wiretap checkpoint (2026-10-26)

**Status: restricted constructive theorem, NOT a practical generic-NP PQ witness-KEM, NOT a standard QPT-LWE reduction.** Full executed Python checker and long-form derivation remain LOCAL ONLY, saved in PQ_WKEM_FULLVIEW_THETA_WIRETAP_TURN9_20261026.tar.xz (SHA-256 f1d5fd4f5649c92562cc1fe13988f8cc15cceba6fceedf56c8b67e0e6db0cf6b). This GitHub note is a mathematical checkpoint, not a claim that the checker is published here.

## Explicit new release

Let C_x over F2 be the earlier sparse factor/one-hot SOURCE matrix. Each actual ORIGINAL witness w gives a distinct binary v_w with C_x v_w=0, (v_w)_0=1 and weight B=1+n+g. Setup already has precommitted claim-scoped native K and public vk(K). Choose X uniform in F2^L, S uniform in F2^(r x L), E with independent Bernoulli(p) entries. Publish the COMPLETE tuple

    (x,context,C_x,p,Y=C_x^T S + E + e0 X^T,
     A,W=A X,H,T=K+H X,vk(K)),

where A is the public parity-check of a reconciliation code, H a public universal linear hash, and + means XOR. Every valid w sees Z_w=v_w^T Y=X+N_w with BSC noise p_B=(1-(1-2p)^B)/2. It decodes X using A Z_w+W, computes K=T+H X and verifies vk(K). All valid ORIGINAL witnesses recover the SAME precommitted K when decoding succeeds. No common witness representation or hidden SourceOpen oracle is assumed.

Unlike the previous direct K-in-Y carrier, a signed false pseudowitness now obtains a noisy observation of the random X, not of K. A *full-public-output* secrecy proof is required; a marginal fake-vector argument is not enough.

## Exact whole-public Fourier theorem

For one m-bit published Y column conditioned on its input X bit b, rho=1-2p, and every character chi_v(y)=(-1)^(v dot y),

    E[chi_v(Y)|X=b] = 1[C_x v=0] rho^wt(v) (-1)^(b v0).

This exactly describes the joint public Y column, **all coordinates and projections**. Put

    Theta = sum_{C_x v=0,v0=1} rho^(2 wt(v))
    d0 = 1 - sum_{C_x v=0,v0=0,v!=0} rho^wt(v).

When d0>0, Walsh inversion, Parseval and 1-h2((1+t)/2)<=t^2 give

    I(X;Y) <= Theta/d0,
    TV(P(Y|X=0),P(Y|X=1)) <= sqrt(Theta).

Proof: uniform C_x^T S eliminates characters outside ker C_x. The conditional density relative to uniform Y is f_even +/- f_odd; f_even>=d0 and E_U[f_odd^2]=Theta. Then I=E_U[f_even(1-h2((1+f_odd/f_even)/2))]<=Theta/d0. This is information-theoretic and is preserved under arbitrary QPT processing of the classical public transcript; it does not imply generic QPT security.

## Certified non-refutable FALSE ORIGINAL case

n=2 Boolean variables, g=4 factors, each excluding one of 00,01,10,11. No ORIGINAL witness exists. The sparse SOURCE has m=17, B=7, rank C=14, and 8 kernel vectors: four normalized v0=1 of weight 9 and four v0=0 of weights 0,10,10,12. Thus a signed normalized pseudowitness exists and the prior public-linear-refutation/perfect-hiding case does NOT apply.

Set p=1/5, rho=3/5. Exact full-public bounds:

    Theta=4(3/5)^18,
    d0=1-2(3/5)^10-(3/5)^12,
    I_false_full<=Theta/d0=0.00041212079768355867 bits/column.

A matching TRUE control (four factors all excluding 00) has three distinct valid witnesses 01,10,11, each obtaining BSC p_B with capacity

    C_honest=1-h2((1-(3/5)^7)/2)=0.000565351806999459.

Strict separation is certified over rationals via binary Pinsker and ln2<7/10:

    C_honest >= (3/5)^14/(2 ln2)
      > (5/7)(3/5)^14 > Theta/d0 >= I_false_full.

The last strict gap is exactly 151785689337873/1028196495361328125 > 0. Exact Walsh inversion independently gives full-public false information 0.00028899334593627743 bits/column. This is a STRICT whole-public channel gap for ONE non-refutable false source, not generic NP secrecy.

## Reconciliation+hash restricted existence

For this fixed finite false channel, fresh independent S,E per column, random public A of rate h2(p_B)+delta < a/L < 1-I_false_full-delta and public universal H with k/L < C_honest-I_false_full-3delta yield asymptotic statistical secrecy of HX from (Y,A,W,H), via random-linear syndrome typical-set coding, AEP/smooth min-entropy and privacy amplification. Then T=K+HX is statistically simulatable from vk(K), and arbitrary QPT postprocessing adds no advantage beyond that separately disclosed native checking key.

**No efficient near-capacity decoder is instantiated.** The simple typical-set decoder is exponential; random dense A costs quadratic bits. Simultaneous correctness over EVERY valid ORIGINAL witness requires a union bound. The small gap suggests >1.7 million columns even for an ideal 256-bit payload before finite-length/error overhead. No cryptographic parameters are claimed.

Offline checker passed 155 counted assertions in two byte-identical runs, enumerating the 8-vector kernel, all 2^17 finite-source noise patterns, exact Fourier inversion and 3 true witness projections. A SEPARATE 12-symbol synthetic code test achieved exact honest one-bit key success 0.9602016037939063 and fake optimal 0.5203099614025625 (284/300 sampled honest decodes); it is NOT an instantiation of the certified false-source capacity gap. Local checker SHA256 0558687257a919899874be084b03c1cf8f096e2903d4ee2bdf43612ff8910c14; captured validation SHA256 34c27375f23dd7399892807ac0cd0d7c4646c7b0693fe0d917b5856ab2dfb798.

## Critical unresolved obligations

The full channel may leak MORE than any one pseudowitness projection. At p=1/14 even this false source has a full-public information rate exceeding the honest projection. At large B, binary p=Theta(1/B) leaves suspiciously sparse E and potential easy public attacks; constant p makes honest capacity exponentially small. This is NOT standard LWE, and no SOURCE-derived complete-output simulator from a QPT-LWE challenge exists. For arbitrary false x, there is no guaranteed channel gap; for hard TRUE x, bare K recovery/native forgery has NOT been reduced to an ORIGINAL witness or independently justified QPT-hard problem. Multi-capsule, malicious N-of-N setup, auxiliary leakage and concrete native Bitcoin graph also remain open. Theoretical existence here does NOT produce a practical generic-NP WKEM.

Exact constructive next step: independently justify a source-coupled q-ary release using standard QPT-LWE challenges that simulates (x,C_x,Y,A,W,H,T,vk(K),aux,related capsules) WITH the SOURCE-opening correlations, then prove arbitrary hard-true key/native forgery => ORIGINAL witness or a separate QPT break.

Research record fullview_thetafiber_wiretap_20261026_turn9; starting checked head 91fb0e1b19e5aa5f91be81e815fc4f9203563194; no external internet research. Keep this PR draft, open and unmerged; production/workflows unchanged.
