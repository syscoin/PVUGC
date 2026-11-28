# R28 — MINK-OR-PSEUDOWITNESS: hard-TRUE OR transport of R19's short public dual

**Research only. NO positive PQ witness-KEM construction advance.** Offline bounded investigation on 2026-11-02. The target is the degree-0 R21/R24/R26/R27 affine Boolean-quotient source, not an arbitrary-degree or nonlinear source. Starting syscoin/PVUGC PR #1 head: 3ba91237c0b830acbf132325f21d0278bff30403 (research/pq-wkem-validation-20260918; draft/open/unmerged); latest substantive ordinary comment 6593280668. Exact-version notes read: R27 ee7473eded3bc1dad24fe61b68c059ce12fe808d; R26 4e9e9f6e47885dc4302a1e9284ced1817b1adc94; R19 c5288b50604f735f940429b0cfd6df8346e87b6. No web or external literature.

## Original affine source and missing implication

For a 3CNF relation phi, let B be the public square-free degree-zero clause-failure coefficient matrix over odd-prime F_q (after sparse row pruning). Let S=[-A|I] be the R27 full-row-rank systematic left-kernel matrix, satisfying SB=0 and ker S=Im B. The classical honest Build draws independent bounded centered errors e for each capability digit mu and publishes the syndrome

    tau_mu = S(e + Delta*mu*e_empty) mod q.

Any valid ORIGINAL witness a gives a Boolean evaluation lambda_a with lambda_a B=0 and lambda_a e_empty=1, so lambda_a=lambda_{a,N} S and Lift returns Delta*mu+lambda_a e. All valid original witnesses obtain the same precommitted native signing capability subject to the joint correctness event, but this does not establish soundness against recovered-key adversaries that do not supply a witness.

## Explicit OR-transported hard-TRUE attack

Use the fixed four-variable FALSE nine-clause formula F from the exact R19 note. There is a publicly computable integer linear functional L_F on its square-free coefficient ring,

    L_F(p) = coeff_empty(p) - coeff_{x0*x2}(p),

with L_F(1)=1 and L_F(g_F,j)=0 for each of its nine degree-zero clause failure polynomials, despite F admitting no satisfying Boolean assignment.

For ANY 3CNF G(y) (including a hard NP witness relation), construct a new proper 3CNF Phi_G using a selector t. Replace each F clause (l1|l2|l3) with the pair

    (t|l1|a_j) AND (!a_j|l2|l3)

and each G clause (d1|d2|d3) with

    (!t|d1|b_j) AND (!b_j|d2|d3).

Auxiliary bits a_j=l2 OR l3 and b_j=d2 OR d3 witness the equivalences to t OR F_j and !t OR G_j. Because F is unsatisfiable, Phi_G has a valid ORIGINAL witness exactly when G does; every such witness requires t=1 and contains a witness of G. There is NO easier substitute witness being assumed.

Define a public Boolean-polynomial substitution T: retain F variables x0..x3, set t=0 and every y=0, set a_j=l2 OR l3 as Boolean polynomials in the F variables, and set b_j=d2(0) OR d3(0), a public Boolean constant. Define L'(p)=L_F(T(p)). The substitution respects square-free Booleanity. For an F gadget, the first clause failure polynomial substitutes to the original F clause failure and the second to zero; for a G gadget BOTH failure polynomials substitute to zero. Therefore, for the genuine public sparse matrix B_Phi,

    L'(B_Phi[:,j])=0 for every mask column j, while L'(1)=1.

Writing ell for the public coefficient vector of L', we have ell B_Phi=0 and ell e_empty=1. Thus ell=omega S for publicly computable omega=ell_N, with no secret and no ORIGINAL witness. The unauthorized adversary simply reads the authenticated public single-base syndrome tau and obtains

    omega*tau_mu = Delta*mu + ell*e mod q.

For errors |e_i|<=eta, the error has absolute magnitude at most eta*||ell||_1. At Delta≈q/2 and q>4eta||ell||_1+O(1), nearest-center decoding returns each protected bit deterministically. Degree-zero sparse row count is at most O(number of clauses); T of a degree-at-most-3 monomial has bounded-size support on the four fixed F variables, giving polynomial ||ell||_1 and polynomial field modulus. This is a classical PPT attack and hence also a QPT attack, regardless of multi-capsule, native signing-key verification, or auxiliary processing. One base suffices; it does not depend on an adversary volunteering an internal representation.

For hard TRUE, choose G as the witness-preserving 3CNF compiler output of a QPT-hard preimage relation f(y)=u, where u=f(y) for a conjecturally QPT-secure one-way function f. Honest Build needs only public u and its own independent native-signing key K, not the hidden preimage y. The attacker above recovers K but not y. Any universal black-box/straight-line extractor interacting with this public classical attacker and witnessless Build can be simulated given u alone; extracting an ORIGINAL Phi_G witness yields an inverter for f. This invalidates the proposed universal hard-TRUE recovered-key-to-ORIGINAL-witness reduction for the DEGREE-ZERO affine source under the QPT one-way assumption. It does NOT establish impossibility for different, genuinely witness-gated source constructions, higher degrees, or a compiler that simplifies the explicit false branch.

## Bounded attempted repair, not a solved source

Every valid witness of Phi_G satisfies t=1. Adding h=1-t as a public masking column preserves every-ORIGINAL-witness correctness and defeats this one pseudo-functional, since L'(h)=1. It is an actual polynomial-ideal consequence: setting s=1-t, x=1-l1,y=1-l2,z=1-l3, the F gadget failure polynomials g1=s*x*(1-a) and g2=a*y*z satisfy s*x*y*z=y*z*g1+s*x*g2. Multiplying the known R19 F refutation by s yields a certificate for h=1-t through these authentic constraints.

This **does not** constitute a secure replacement. No claim is made that remaining low-noise fake decoders have disappeared, nor that finding sufficient global consequences can be done in PPT for arbitrary NP. It is a single semantic column repair with no new full-public QPT security or native recovered-key extractor. Padding, scalar LWE keys, public basis changes and supplied-representation-only claims remain insufficient.

## Exact computation, assumptions and security scope

The independently authored offline standard-library Python checker executed twice with identical SHA-256 output fc938af729236cf607d2aeb2681f6f28371cf891bba279f4c654d1fbc0e0279b: 4,534 assertions each; explicit 20-variable 24-clause true OR source (F=9 clauses,G=3 clauses), 74 public square-free coefficient rows, rank 24, 50 systematic syndrome symbols, nine nonzero pseudo coefficients with L1=9; 5 distinct valid G witnesses; 1,024/1,024 classical unauthorized full-view bit recoveries and 128 direct systematic-syndrome recoveries at q=65537, Delta=32768, eta=1. Checker confirms all 16 F assignments are invalid, all 256 base x/t/y assignments obey OR semantics, exact clause substitution identities, mask annihilation, pivot/systematic row identities, and the bounded h repair. The G fixture is illustrative, not an instantiated QPT-hard f.

The attached JS checker and exact captured output also execute twice identically in the connected JS runtime and independently check the decisive Boolean polynomial identities, OR semantics, bounded error and single-base release. Tests establish finite algebra, not quantum hardness. The asymptotic hard-TRUE claim is CONDITIONAL on independent QPT OWF hardness and the explicit witness-preserving 3CNF compiler.

The full public view includes ORIGINAL relation/statement, capsule, genuine native vk, public checking key, claim/UTXO, source branches, anchors/window/context, auxiliary data and related scopes. In this attack those extra fields are retained honestly and cannot un-leak a recovered K; no challenge-base private opening is needed. A generalized adversarial-FALSE joint-QPT simulator, a safe hard-TRUE extractor, malicious one-honest N-of-N preauthorization/abort, pre-funding DA and conditional native no-EC Bitcoin endpoint all remain UNPROVED. No ordinary QPT-LWE reduction is invoked.

## Next exact missing release equation

Construct a classically PPT, polynomial-size, genuinely globally witness-gated Build/Lift such that every valid ORIGINAL witness w recovers the SAME bound K, while for every unauthorized QPT key-recovery/native-forgery adversary A WITHOUT supplied internal representation there exists an independent-PQ-break-or-ORIGINAL-witness extractor. In particular rule out publicly computable fake-evaluation vectors transported through OR branches, not just the one short ell exhibited here. Instantiate the full joint-public QPT FALSE simulator with native checking-key, auxiliary, malicious graph and selective-opening correlations. Neither this hard-TRUE attack, the local h mask, nor any previous basis projection satisfies those conditions.

**Run status: NO positive construction advance; no scheduled-task completion.**
