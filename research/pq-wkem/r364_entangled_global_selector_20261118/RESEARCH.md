# R364 — entangled global-bit selector for public source release (NONQUALIFYING)

## Provenance
Inspected the actual open/draft PVUGC PR #1 on branch research/pq-wkem-validation-20260918, head 1832225d60d38f49f9c01edc408723521ffb0913 (R363), and exact R363 note blob 91b550244d09b62b91633f5d200dfd2a97a35021. Latest relevant issue comment remained R225. No web, Core source, production changes or native-signature runs. This continues R363's unfinished step: find a publicly serialized, source-dependent NONLINEAR evaluator, jointly with its full-public simulator, rather than merely an opaque exact-support matrix program.

## Candidate: a nonseparable global selector
An attempted change from R363's publicly composable ABP transitions is to publish a genuinely coupled selector for two repeated occurrences of ONE bit x, rather than local selectors independently splicable by an attacker. Over an odd-characteristic field define v_0=(1,0,0,1)^T, v_1=(1,0,0,-1)^T, P_b=(1/2)v_b v_b^T. Each P_b is a 4x4 rank-one projector (P_b^2=P_b; P_0 P_1=0), but neither is a tensor product of 2x2 rank-one projectors. Both partial traces are I_2/2 for both b, while the GLOBAL observable X tensor X distinguishes b: Tr[P_0(X tensor X)]=1, Tr[P_1(X tensor X)]=-1. This breaks the premise that every publicly selectable state can be decomposed into publicly distinguishable one-occurrence bit labels.

The precise obstacle is that for ANY local 2x2 observable A,
    Tr[P_0 (A tensor I)] = Tr[P_1 (A tensor I)] = (1/2)Tr(A).
No local linear clause evaluator can tell x=0 from x=1, even though a global evaluator can. Therefore any construction with such perfectly hidden local marginals must pay for a genuine nonlocal, global consistency computation. It is not enough to change the selector basis or hide individual labels.

## Tested local attempted repair and FALSE splice
The simplest way to give clauses separately readable shares immediately restores the old mixing attack, despite the entangled selector. Let S be a frozen field-valued cancellation secret, r an independent nonzero scalar, and publish E_1=r S P_1, E_2=r^(-1) P_0. A COMMON input b yields
    F(b)=Tr(P_b E_1) Tr(P_b E_2)=0
for both b=0,1, exactly modeling the FALSE constraint x AND NOT x. But the entire public serialized view permits two inconsistent evaluations:
    Tr(P_1 E_1) Tr(P_0 E_2)=(rS)*(r^(-1))=S.
The unqualified adversary recovers S without producing any common satisfying witness. A public global checker added after these raw readouts cannot repair the already released information. This is only a regression for this attempted construction, not a generic impossibility of nonlocal tensor/quantum-inspired hash-only witness encryption.

## Executed checks
A standard-library CPython checker was run TWICE with byte-identical JSON: over F_257, S=173, r=41, it checked projector idempotence, equal local marginals, opposite global correlations, consistent FALSE output zero, and split recovery of exactly 173. 13 algebraic assertions per run. Exact local checker SHA256 1232da2dce830ea27123a5d58272cac26c924e01cad42bac1b14bed9ad01b462; paired output SHA256 51f40b0fc330e4d8b09fc532741f23d79e877a93f787789383f19e301cca9683. Detailed derivation, checker and two output copies remain LOCAL ONLY at /mnt/data/R364_entangled_selector_local_20261118.tar.gz, archive SHA256 815a03c36ff4fdf7697dabbb0823839884d83d2565ce9f2657cce42198bc9daf. The synthetic arithmetic is not authentic SHA/AuxPoW, Bitcoin best-chain evidence, native cancellation signing or a quantum security test.

## Exact missing step
The ONLY useful next step is a classical-PPT source-dependent serialized Build_inc(x_W,S)->C and public Open_inc(C,w)=S for every distinct qualifying ORIGINAL source certificate, without accessible inconsistent local readouts, plus FALSE/hard-TRUE full-public QPT recovery/forgery reduction to an ACTUAL qualifying ORIGINAL certificate or independent justified PQ hash/native break, with malicious setup/source generation, siblings and selective openings. Neither an entangled selector nor a global software if-check provides this. Original OR challenge grounds, strict postactivation modern AuxPoW chain ID and canonical 41-byte SYS tag, actual ancestor and LC-depth qualification, R225 activation binding, and N-of-N honest-erasure setup remain unchanged.

NONQUALIFYING: no ORIGINAL WKEM breakthrough, no progress comment, no deployment, approval, merge, production edit or automation change.
