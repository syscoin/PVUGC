# R159 — Witness-invariant LWE columns: total-relation coNP-complete subproblem

**Research status: routine negative foundational check, not a generic PQ WKEM, not a notification-level breakthrough.** No optimization or external internet research. Exact prewrite PR #1 head e74b7dfce73b5d3249b8d71c6c05a27ea0ba789a; branch research/pq-wkem-validation-20260918, open/draft/unmerged. Immediate R158 exact file blob 7bd79bd30185b4391cc8601829da558741790216; R157 exact file blob a5a5d2325ce06e836765e208ebbb86c1828a2c74. Latest substantive ordinary comment 6718361572 (R153).

## Candidate/source law and indispensable repair

R158 attempted to add genuinely independent LWE source columns to a common-bit phase. Work over F_q with an odd prime q. Honest classical setup samples r uniform in F_q^k, R uniform in F_q^{m x t}, u uniform in F_q^t, and genuine bounded integer errors e,e0. For every ORIGINAL witness w suppose a polynomial-time representation z_w satisfies G_x z_w=b_x; different valid w need not share any internal state. Publish x,G_x,b_x,R, c=G_x^T r+R u+e mod q, t0=b_x^T r+Delta K+e0 mod q, and any checking key J/CK/Aux, native VK, sibling capsules and context. Witness w computes

    t0-z_w^T c = Delta K+e0-z_w^T e-z_w^T R u (mod q).

For the same bounded-noise phase decoder to recover a common K from every valid ORIGINAL witness, independently hidden u cannot leave an uncontrolled, witness-dependent residual. If D_x is the F_q span of all differences z_w-z_w' over valid w,w', then each uncompensated column rho of R must lie in D_x^perp. R158 proved independent uniform columns do not satisfy this in general; if columns are publicly derived as G_x^T H, they simply merge into the existing uniform r.

Here the explicitly named repair attempt is: derive a genuinely new allowed random column from the exact space D_x^perp using only the public ORIGINAL statement (and even a provided public satisfying witness). This note tests the computational requirement of that proposal instead of optimizing its dimensions.

## Exact elementary theorem

For any Boolean circuit phi(y) on n input bits, define another ORIGINAL verifier

    V_phi(b,y) = ((b=0) AND (y=0^n)) OR ((b=1) AND phi(y)=1).

The verifier is always satisfiable: the fallback witness (0,0^n) is publicly known. Define the public representation z_(b,y)=(1,b) over F_q; all valid witnesses obey the public linear consistency equation G z=1 for G=[1,0]. Consider the proposed random-column direction rho=(0,1), so rho^T z=b.

This column is invariant across all valid ORIGINAL witnesses **if and only if phi is unsatisfiable**. If phi is satisfiable, a second valid witness (1,y*) evaluates rho to 1 while the public fallback evaluates it to 0. If phi is unsatisfiable, only the b=0 fallback exists.

Thus deciding whether a specified public column lies in D_x^perp is coNP-hard by the many-one reduction Circuit-UNSAT -> this membership question, *even on a promised-satisfiable ORIGINAL relation with one witness supplied*. It belongs to coNP: a witness of nonmembership is a pair of valid ORIGINAL witnesses with distinct column evaluations. Consequently the decision problem is coNP-complete for generic polynomial-time Boolean verifier relations (under standard many-one reductions). This is an ordinary deterministic complexity classification, NOT proof NP != coNP, an inference about quantum hardness, or a theorem ruling out every possible cryptographic source compiler.

For any public linear rho=(a,beta), its evaluation a+beta b is invariant across all valid witnesses iff beta=0 OR phi is UNSAT. The always certified beta=0 part is exactly the rowspace of G; setting R=G^T H and shifting the phase by b_x^T H u leaves the **whole base source (c,t0) marginal law** unchanged when r is uniform. This marginal identity does not imply full-public J/CK/Aux identity if those fields retain u or secret-dependent information.

When beta != 0 and phi SAT, a fallback witness and an alternate witness have distinct phases differing by beta*u. For fixed nonzero beta and uniform u, this difference is uniform on F_q: Pr[phase equality]=1/q. For beta and u both uniformly independent, Pr[equality]=(2q-1)/q^2. Neither yields the required simultaneous narrow-phase correctness. If phi UNSAT, beta need not vanish but selecting such an extra invariant via exact generic membership requires solving the coNP-complete problem above.

Nonlinear syntactic invariants such as constraint multiples can be generated without this decision, but their mere algebraic constancy does not manufacture an independent ordinary-QPT-LWE challenge or a jointly secure release. The invariant-computation hardness is a limit of **this repair subroutine**, not a full impossibility result for nonlinear sources.

## Precise obligations and handoff

Honest setup/evaluation are classical PPT only if every algorithm including candidate invariant sampling is classical PPT. Threat model: arbitrary nonuniform QPT with quantum advice, maliciously correlated keys and capsules, auxiliary context, classical selective opening. This run provides **no** full-public QPT simulator, source IND-CPA, fixed-FALSE hiding, hard-TRUE arbitrary final-key recovery to ORIGINAL witness, native EUF-CMA composition, malicious N-of-N setup/abort, graph/data-availability guarantees, parameter calibration, or Bitcoin PQ endpoint. No SourceOpen oracle or adversary-volunteered internal representation. Original binding must include relation identity, claim/UTXO, branch, anchors/window, context, native VK and intended capability. Bitcoin must not execute NP verifier/proofs; conditional P2MR-like no-EC-key-path and SLH-like endpoint are not deployed claims.

Do not revive the R158 independent-column repair by computing D_x^perp exactly for arbitrary ORIGINAL relations: membership is coNP-complete even when one witness is publicly known. Known rowspace columns are QPT-source-distribution redundant. The next genuine source must *jointly* instantiate a nonlinear ORIGINAL-dependent public capsule, every-witness same-capability opening, and a straight-line full-public ordinary-QPT-LWE simulator, then handle arbitrary unauthorized recovery/native forgery via actual ORIGINAL extraction or independent QPT break. No positive security obligation closed. Do not post a routine top-level PR comment or notify the user.

## Executed Python 3 standard-library checker

    #!/usr/bin/env python3
    import json
    assertions=0
    def ck(a,msg):
        global assertions
        assertions+=1
        if not a: raise AssertionError(f'{assertions}: {msg}')
    def witnesses(table,n):
        return [(0,0)]+[(1,y) for y in range(1<<n) if (table>>y)&1]
    counts=[]
    for n in (1,2,3):
        total=1<<(1<<n)
        noextra=0
        for truth_table in range(total):
            ww=witnesses(truth_table,n)
            ck(ww[0]==(0,0),"fallback witness")
            ck(len(ww)==1+truth_table.bit_count(),"witness count")
            invariant=len({b for b,_ in ww})==1
            ck(invariant==(truth_table==0),"invariant iff UNSAT")
            rho_values={b for b,_ in ww}
            ck((rho_values=={0})==(truth_table==0),"column safe iff UNSAT")
            ck(len({1 for _ in ww})==1,"rowspace correction")
            if invariant: noextra+=1
        counts.append({"variables":n,"formulas":total,"invariant_instances":noextra})
    q=7
    for table in range(1<<(1<<3)):
        ws=witnesses(table,3)
        for a in range(q):
            for beta in range(q):
                v={(a+beta*b)%q for b,_ in ws}
                ck((len(v)==1)==(beta==0 or table==0),"linear invariant")
    prob=[]
    for q in (5,7,11,13):
        count=sum((beta*u)%q==0 for beta in range(q) for u in range(q))
        ck(count==2*q-1,"zero product count")
        prob.append({"q":q,"zero_count":count,"total":q*q})
    result={"run":"R159-ORIGINAL-INVARIANT-COLUMN-HARDNESS-20261108","assertions":assertions,"cases":counts,"phase_law":prob,"interpretation":"Finite confirmation only. Worst-case coNP-completeness is proved by circuit reduction, not experiment; no QPT or LWE security claim."}
    print(json.dumps(result,sort_keys=True,indent=2))

The exact executed local checker used the same loops/assertions with more commentary and printed 13,928 passing assertions; two executions yielded byte-identical output. Local file /mnt/data/r159/checker.py SHA-256 34239b8d7eaf98ed24b2aa3729922046ce82da8d045545e0a026b39e120bbd82.

## Captured counts

    {
      "assertions": 13928,
      "cases": [
        {"formulas":4,"invariant_instances":1,"variables":1},
        {"formulas":16,"invariant_instances":1,"variables":2},
        {"formulas":256,"invariant_instances":1,"variables":3}
      ],
      "phase_law": [
        {"q":5,"total":25,"zero_count":9},
        {"q":7,"total":49,"zero_count":13},
        {"q":11,"total":121,"zero_count":21},
        {"q":13,"total":169,"zero_count":25}
      ],
      "run":"R159-ORIGINAL-INVARIANT-COLUMN-HARDNESS-20261108"
    }

The full exact captured output is local-only /mnt/data/r159/captured.json SHA-256 95f4a44a3b00e1bc47973e5c2f2da2799ddda7053a541c4c1721be8cb35b639a. Checks are finite algebra; they do not establish QPT security or replace the unconditional circuit reduction. No independent agents or external literature used.
