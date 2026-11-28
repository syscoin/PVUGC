# Hidden reject-map matrix gate — nonqualifying original-source iteration (2026-11-23)

## Continuity / source
At research start, the open/draft syscoin/PVUGC PR #1 branch `research/pq-wkem-validation-20260918` had SHA `3c53ad0e515fdc8539e177091bc52edc4d5846f5`; the directly preceding canonical-proof-hash note was blob `68e217c8d9503e35210e4a1fe61dc02efbd88905`. Also read global-certificate-label note blob `460917f0d66a4f0cbed93774ff246bf3e502143d` and the relevant source-matrix-automaton note blob `37abc1718fbed8bef0cccbdb587cd4f6edaa020e`. Top-level comments since 2026-11-21 returned []. No web, external literature, Core source/test execution or Bitcoin/Syscoin certificate was used.

The goal has NOT changed: public classical-PPT Build/Open must release the same frozen safe cancellation capability for *every* qualified ORIGINAL three-branch OR witness, including claim/outpoint, burn/recipient/amount/reserve/replay, BTC baseline/anchors/work, actual conflicting Syscoin ancestry under strict post-PQ tag/chain-ID policy, LC depth, windows, reset, deadline, native message/VK and capsule ID. No greater Syscoin-work test, second responding notary, or assumed online release oracle.

## One named candidate and mathematical change
The earlier public weighted matrix automaton had scalar P(w)=K*R_x(w). Its publicly enumerable suffix spaces recover a qualifying word, so merely adding random GL gauges does not help. Attempt instead a *noncommutative constant-on-TRUE / diverse-on-FALSE gate*:

- Choose private independent U,V uniformly in G=GL_d(F_q); K=U^{-1}V.
- For full source certificate w, define T_x(w)=I if R_x(w)=1, else J(w), where J is proposed secret keyed pseudorandom invertible matrix output.
- A hypothetical public evaluator would return P_x(w)=U^{-1}T_x(w)V.
- For a synthetic group payload S publish D=S*K. Every qualifying w gives P_x(w)=K, and D*P_x(w)^{-1}=S. Different fork/witness states need not share any secret, preimage, label or hash.

This is an **interface**, not an implemented Build. Varying invalid outputs removes the *literal* nonzero-vs-zero suffix-span test; it is not yet security.

## Why using SHA-derived, PUBLIC invalid matrices fails
The tempting hash-only choice is J(w)=Phi(w), an invertible matrix computable from public SHA256d(w) and domain tags. From three arbitrary INVALID w_i an adversary computes Phi_i and also the evaluator output P_i=U^{-1}Phi_i V. Without any valid source certificate, the attacker constructs the HOMOGENEOUS LINEAR equations

    A*P_i=Phi_i*B                   (1)

in the 2d² unknown entries of A,B. To see when this reveals K, suppose U,V are true invertible solutions, and let X=A*U^{-1}, Y=B*V^{-1}. Then X*Phi_i=Phi_i*Y. The first equation determines Y=Phi_1^{-1}X*Phi_1; all other equations require X to commute with Phi_i*Phi_1^{-1}. If the joint centralizer of Phi_2*Phi_1^{-1} and Phi_3*Phi_1^{-1} consists only of scalar matrices, every solution is (A,B)=t(U,V). Any nonzero solution has invertible A and reveals

    K=A^{-1}B=U^{-1}V,     S=D*K^{-1}.

The centralizer condition is explicit; no claim is made that *every* public SHA triple satisfies it. This is a classical invalid-input attack, does not rely on scalar finite covers (R366), public suffix/nonzero acceptance detection, source witness inversion, or an adversary-volunteered representation.

## Exact FALSE joint-*function* model (NOT a public capsule)
For diagnosis only, take J as an *independent ideal uniform random function* from invalid witnesses to GL_d(F_q). On a FALSE instance every P(w)=U^{-1}J(w)V is independently uniform, even conditioned on K=U^{-1}V. Since K is uniform, D=S*K is uniform and independent of the entire function P for any fixed group S. This is an exact two-way distribution coupling even under coherent ideal-function query interfaces. Independent parameters permit the same restricted oracle-level statement for independent sibling group payloads. It does NOT simulate serialized public bytes, source/native VK correlations, malicious retained setup/source coins, selective openings, or a concrete SHA/QPT adversary. A KDF and native signature byte encoding have not been built.

The attempted repair J=PRF_a(w) has a short *PRIVATE* description, but **no specified practical public compiler** for P_x exists which hides a,U,V and enforces R_x inside cryptographic evaluation. Publishing a or public Phi enables the attack; an exponential list of random J values violates practical PPT; postulating a protected SourceOpen or FE evaluator is exactly the missing foundation. Ordinary hash/PRF security is not white-box FE security.

## Executed local bounded check and provenance
A Python3 standard-library finite-field Gaussian-elimination checker actually ran twice with byte-identical JSON outputs. It sampled synthetic random U,V,Phi_i over F_103 for d=2,3,4 and 2,3,4 invalid pairs. For two pairs, homogeneous nullity was d. For three and four pairs, all three tested dimensions had nullity 1 and recovered K exactly (true-key equality asserted). This checks only the finite-field equation and its centralizer phenomenon; NOT SHA source, original bridge witnesses, native signatures, an FE construction, or quantum security. No probability estimate for generic inputs is inferred from these fixtures.

- Checker SHA256: `f852946899191266650a43ce7b8ec2b922906c9ee852e8be7a3d52b089e657ff`
- Both captured output SHA256: `7a3968dbbd5a20d7f5584f78b380118b1acbd41bb99e28d859e8b69ab7b79e43`
- Local-only full derivation, executable checker and two outputs archive: `/mnt/data/pq_wkem_run_20261123.tar.gz`; SHA256 `42c03afcbe5bbe4bc817d2c4ca126dfa8e94704317fe76b2e847ac2bc1355394`. No persistence between executions is assumed; do not treat this GitHub note as publishing checker/output bytes.

## Outcome / exact unfinished equation
**NONQUALIFYING.** The diverse secret reject-map direction avoids the old scalar zero/nonzero attack at the algebraic interface, but public SHA-derived reject maps expose K by invalid-only linear equations. No serialized classical-PPT public evaluator of a hidden keyed reject map; no full-public FALSE/hard-TRUE QPT security, malicious setup, native forgery/work-budget reduction, or ORIGINAL qualified source-to-frozen capability exists. Not a hash-only witness KEM, not a Bitcoin/Syscoin source result.

    Build_inc(x_W,sigma_cancel;rho) -> publicly serialized C   [MISSING]
    Open_inc(C,w) = identical safe frozen capability for EVERY R_orig(x_W,w)=1
    Unauthorized full-public recovery/native forgery
       -> actual ORIGINAL qualifying certificate OR independent QPT primitive break.

The next candidate must instantiate a *cryptographically protected globally source-conditioned evaluator* with an independently proven joint-public security reduction. It cannot rename J as an oracle, move the unknown key into a public source hash, or claim the ideal FALSE coupling as an implementation. No user breakthrough notice, PR comment, Core/production edit, deployment, permissions or automation changes.