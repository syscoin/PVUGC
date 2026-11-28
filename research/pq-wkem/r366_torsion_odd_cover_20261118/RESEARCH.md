# R366: 2-torsion repair of the global tensor, defeated by an odd Ch-gate cover (NONQUALIFYING)

## Provenance and actual scope
Live open/draft syscoin/PVUGC PR #1 research/pq-wkem-validation-20260918 was inspected at 633524510213a2855cdeae84bdb1cb2b8b6d9f55 (R365). Exact R365 note blob ad9490e4008e123b53675fe505d4da2defe3f041 and R364 precursor were read. Issue comments since 2026-11-16 22:51 UTC returned no new comments. No Core source reread, network admission, actual source certificate or native signing was needed/performed.

The precise R365 two-cover extraction was Z_2=K^2 from its completely PUBLIC tensor entries. A specific mathematical repair is to change the secret distribution to the order-two subgroup G={+1,-1} inside F_103*: then Z_2=1, which conveys no secret. This run tests whether any odd cover remains, rather than merely resampling R365's old attack.

## Public Build/Open (synthetic, **insecure**)
For each Boolean variable v with d local-clause occurrences, sample independent invertible 2x2 matrices A_(v,j),C_v over F_103 and publish the small copy tensor

T_v[i_1,...,i_d,k] = SUM_(b=0,1) C_v[k,b] PRODUCT_j A_(v,j)[i_j,b]

and both psi_(v,b)=C_v^(-T)e_b. For each arity-four constraint c_j(a) publish Q_j[i_1,...,i_4] = K_j SUM_(a:c_j(a)=1) PRODUCT_(v=1..4) (A_(v,j)^(-T)e_(a_v))[i_v], with K_0=K and K_j=1 for j>0; publish ciphertext D=S*K with K,S in G.

The PUBLIC party contracts T_v with psi_(v,b) and explicitly factors the rank-one result. This gives tilde_a_(v,j,b)=s_(v,j,b)A_(v,j)e_b with PRODUCT_j s_(v,j,b)=1. It can then form local PUBLIC readouts

v_j(a) = contract(Q_j, {tilde_a_(v,j,a_v)}_v) = K_j c_j(a) PRODUCT_v s_(v,j,a_v).

For any whole assignment w, PRODUCT_j v_j(w)=K PRODUCT_j c_j(w). Thus prescribed Open yields the same K for every satisfying w, and zero for every nonsatisfying w. Full public processing, not prescribed Open, determines security.

## Cover calculation
Choose k locally accepted assignments for each clause j with, for every variable v and bit b, the same number m_(v,b) of occurrences of b at EVERY clause containing v. The adversary can publicly multiply their v_j values:

Z_k = PRODUCT_j PRODUCT_(t=1..k) v_j(a_(j,t))
    = K^k PRODUCT_(v,b) (PRODUCT_j s_(v,j,b))^m_(v,b)
    = K^k.

This algebra uses only public tensor factorization plus local allowed assignments. It does NOT require any common satisfying witness or knowledge of private gauges. K in the 2-torsion subgroup eliminates exactly the even-cover leak, not odd covers. If both k=2 and k=3 covers exist, K=Z_3/Z_2 for *any* nonzero scalar K in the field.

## Concrete FALSE Ch-gate example and explicit covers
Variables (x,y,z,t); Ch(x,y,z)=(x AND y) OR ((NOT x) AND z).
A: t=Ch(x,y,z).
B: t=Ch(x,z,y).
C: y != z (represented as a four-ary relation, ignoring x and t).

The conjunction is FALSE: when y!=z the two Ch outputs must be opposite, so cannot both equal t. But two balanced covers exist. Each four-bit word below is in order xyzt, and every word is locally accepted:

k=2: A {0000,0111}; B {0000,0111}; C {0010,0101}.
     All three clause multisets have bit-one counts (0,1,1,1).

k=3: A {0000,0111,1010}; B {0000,0010,1111}; C {0010,0010,1101}.
     All three clause multisets have bit-one counts (1,1,2,1).

Thus the complete PUBLIC FALSE capsule yields Z_2=K^2=1 and Z_3=K^3=K for G={+1,-1}. The attacker obtains S=D/Z_3 without an ORIGINAL source certificate. In arbitrary nonzero scalar subgroups the ratio Z_3/Z_2=K also defeats attempts to choose a different finite key order. These are real Boolean Ch equations but NOT a complete SHA256 trace or qualified Bitcoin/Syscoin bridge relation.

## Executed validation, local-only sources
A standard-library Python checker was actually invoked twice with success statuses and byte-identical outputs. It constructs explicit full PUBLIC copy tensors T, psi, Q, D from random invertible matrices, extracts the rank-one public factors and clause readouts without private gauge access, exhaustively checks the 16 global assignments are FALSE, verifies both public covers and K/S extraction for eight seeded keys including -1, and separately verifies eight satisfying assignments on a TRUE triple-Ch fixture recover one identical key.

check.py SHA256: 7d2b79794a219ec99282495fa11eb9ebd96e1aa2c2712f7869bbbd7ad426ae21
output1.json and output2.json SHA256: eef9cad9d77bdcfafb13a3cf47dd6f1bc3a0a7e0fef90ea598a5cfd54c7d0953
Local-only archive: /mnt/data/R366_torsion_odd_cover_20261118.tar.gz SHA256 357b5e048c3cfefe31147577873e6b40a9614fa661d79d3ea7e899d94d1c8cd0. The checker/output bytes are NOT committed in this note.
An initial paired shell invocation timed out after the first output was written; it is not treated as a successful paired run. Both executions were then rerun and completed successfully with matching hashes.

## Security and next step
The 2-torsion change genuinely blocks the previous *specific* Z_2 inversion but still fails on a 3-cover in this simple nonlinear gate system. This neither establishes a generic hash-only impossibility nor breaks SHA/AuxPoW. No public classical-PPT Build_inc(x_W,sigma_cancel)->C/Open_inc(C,w)=same frozen native capability for EVERY qualifying ORIGINAL strict-post-PQ source certificate was constructed. No FALSE/hard-TRUE QPT reduction, malicious-source/setup/capsule proof, or R225 native activation binding was supplied.

A meaningful replacement must prevent all finite-cover and mixed-evaluation leakage by an ACTUALLY SERIALIZED public *global* source-dependent evaluator, jointly with a full-public FALSE and hard-TRUE QPT simulation/reduction to an actual relevant Bitcoin/Syscoin certificate or an independently justified PQ hash/native break. No private/ideal SourceOpen, raw invalid-trace pads, source-generated secrets, arbitrary Hash puzzles, hidden online signer, or generic-NP WE assumption is a substitute.

NONQUALIFYING: research note only; no PR progress comment, user breakthrough notification, Core/production edit, deployment or automation change.