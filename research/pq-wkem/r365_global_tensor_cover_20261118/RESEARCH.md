# R365: Gauge-coupled global Boolean tensor capsule and the two-cover failure (NONQUALIFYING)

## Source and purpose

Live draft PVUGC #1 was read on branch research/pq-wkem-validation-20260918 at d1e09a2a9c2bbd7f531460ff635bb9568539f045 (R364); its note blob was 52b22caf78d25f730b9a4cb3c0740299fa4489e1. R363's publicly exposed finite-width arithmetic branching program and R364's split local readout motivated an actual mathematical change: combine all repeated occurrences of an input bit in one PUBLIC copy tensor, with no separately published raw clause labels. Ask simultaneously for a classical-PPT serialized Build/Open and a complete-public FALSE simulator. The candidate is source-independent Boolean algebra, NOT an ORIGINAL SHA/AuxPoW WKEM, and ultimately fails the latter security task.

No web, literature, Core tests, actual source certificates, native signatures or quantum computation were used. The strict PQ canonical modern AuxPoW rules are not identified as defective. R316's identical lagged tags do not refute authenticated history-conflict detection at qualified source depth.

## Public serialized construction (correct but INSECURE)

Let q be an odd prime and let a CNF have bounded clause arity and bounded occurrence per variable. For each variable v and occurrence j independently sample A_(v,j) from GL_2(F_q) and a boundary C_v from GL_2(F_q). Erase these secret setup matrices after construction. For degree d_v, publish the (d_v+1)-order copy tensor

    T_v[i_1,...,i_d,k] =
        SUM_(b=0,1) C_v[k,b] * PRODUCT_j A_(v,j)[i_j,b],

along with psi_(v,b) = C_v^(-T)e_b. These are explicit finite arrays of size 2^(d_v+1). For bounded fanout, their aggregate publication size is polynomial.

Any public evaluator can contract T_v against psi_(v,b), yielding the rank-one slice

    U_(v,b)[i_1,...,i_d] = PRODUCT_j A_(v,j)[i_j,b].

Factor this PUBLIC rank-one tensor by choosing a nonzero pivot cell. Normalize the first d-1 column factors by the pivot cell and place the remaining pivot amplitude in the last factor. The resulting columns tilde_a_(v,j,b) have the form s_(v,j,b) A_(v,j)e_b with PRODUCT_j s_(v,j,b)=1 for each fixed v,b. The factorization is deterministic and polynomial in the published array size. It does not invoke a hidden evaluator or witness oracle.

For each clause j with local accept predicate c_j(a), publish the tensor

    Q_j[i_1,...,i_t] =
        K_j * SUM_(a:c_j(a)=1) PRODUCT_l
                       (A_(v_l,j)^(-T)e_(a_l))[i_l],

where K_0=K (the setup-frozen nonzero field key) and other K_j=1. For an input assignment w, compute

    v_j(w) = contraction(Q_j, tilde_a_(v_1,j,w_v1), ...)
           = K_j * c_j(w) * PRODUCT_l s_(v_l,j,w_vl).

Then the PUBLIC algorithm

    Open(C,w)=PRODUCT_j v_j(w)
             = K * PRODUCT_j c_j(w)

returns the SAME K for EVERY satisfying assignment, regardless of the private gauges. Any unsatisfying input gives zero under this *prescribed* evaluation. This is an actual public classical algorithm and a polynomial-size serialized encoder for bounded-occurrence constraints. Both are **insecure**, because the attacker is free to process public tensor entries in ways other than Open.

The executed TRUE fixture forbids 00 and 01 in two Boolean variables; it has distinct satisfying assignments 10 and 11, each of which returns identical K.

## Exact full-public FALSE coupling for a restricted unary contradiction

For the FALSE formula x AND NOT x, use three independently random invertible 2x2 gauges A,B,C and publish

    T[i,j,k] = SUM_b A[i,b] B[j,b] C[k,b],
    u=A^(-T)(K e_1), v=B^(-T)e_0,
    psi_b=C^(-T)e_b, D=S*K.

Take both K and S in the order-51 QR subgroup G of F_103^*. Prescribed evaluation of T,u,v,psi_b is zero for BOTH b. The complete public capsule includes the arrays, both selectors and D.

For any fixed alternative S' in G, set K'=K*S/S', t=K'/K, A'=A*diag(1,t), B'=B*diag(1,t^(-1)), C'=C. Then every public T,u,v,psi_b,D entry is BIT-FOR-BIT identical: the tensor's column scalings cancel, u'=K'/t A^(-T)e_1=u, v'=v, and D'=S'K'=SK. The map on independent uniform gauges and uniform K is a distribution-preserving bijection. Therefore THIS VERY RESTRICTED FALSE public distribution has an exact complete-public simulator for any messages in G (and hence for coherent quantum processing of identical classical public data), provided auxiliary input does not correlate with secret gauges and there is no native VK/signature/message correlation. This result does not handle the ORIGINAL relation, arbitrary native signatures, malicious setup, or sibling selective opening.

The checker constructed and verified 24 deterministic switched-parameter pairs with unequal S,S' and equal complete public arrays/ciphertext, not just equal prescribed function outputs.

## Four-clause FALSE witness destroys the security extension

Set variables x,y and four 2-variable clauses indexed by the forbidden local assignment: 00,01,10,11. The conjunction is FALSE for every x,y, and the prescribed Open always returns 0. Build the same tensor capsule with K in G.

From PUBLIC T and selectors, extract all tilde_a factors. For every clause j and locally accepted pair a, compute v_j(a) by contracting PUBLIC Q_j with those factors. These are PUBLIC values; no qualifying source witness and no private gauge is needed.

For each clause choose TWO locally accepted COMPLEMENTARY pairs:

    forbidden 00 or 11: choose 01 and 10;
    forbidden 01 or 10: choose 00 and 11.

Let (a_j,bar_a_j) be the chosen pair. Every variable's bit 0 and bit 1 occurs once in each chosen pair, for every clause. Thus a publicly computed eight-value product satisfies

    Z=PRODUCT_j v_j(a_j)*v_j(bar_a_j)
     =PRODUCT_j K_j^2 * PRODUCT_(v,b) PRODUCT_j s_(v,j,b)
     =K^2.

The factor scales cancel by rank-one slice normalization. Since G has order 51, the attacker computes K=Z^26 because 2*26=1 mod 51. If D=S*K the attacker also recovers S=D/K. This is a CLASSICAL unauthorized full-public FALSE extraction, despite global coupling and absence of a single satisfying witness. It is a degree-two locally consistent cover / fractional pseudoassignment, not a valid common source certificate.

This differs technically from R364's explicit separately published raw readouts: the attacker FIRST factors completely public GLOBAL copy tensors, and only then reconstructs local values. It also differs from R363's virtual repeated matrix words: here all public operations are finite tensor slices and contractions, with the mismatch occurring between two locally consistent copies.

The executed code used 24 distinct seeds for this full-public FALSE recovery (each fixture checked all four legal assignments return zero) and 24 TRUE seeds checking two distinct witnesses produce the same key. A second execution of each checker produced byte-identical JSON. None of these synthetic tests invokes SHA/AuxPoW admission or quantum hardware.

## Why the security repair is still missing

The tensor construction demonstrates the *simultaneous* local correctness and full-public-simulator calculations on a narrow FALSE instance. It DOES NOT give a QPT-secure ORIGINAL source-release foundation. A plain publicly computable post-check of source validity cannot repair already recoverable raw tensor invariants. Hashing locally readable factors is not a construction of a publicly evaluable, globally nonhomomorphic merge that returns one K for all valid ORIGINAL witnesses.

The next useful equation is a genuinely classical-PPT, serialized global source-dependent encoding whose complete PUBLIC view is resistant not just to inconsistent single clause readouts but to ALL finite-cover pseudoassignments (including this explicit k=2 attack), jointly with a FALSE and unauthorized hard-TRUE QPT simulator/reduction to an ACTUAL relevant authenticated Bitcoin/Syscoin source certificate or an independently justified PQ hash/native break. It cannot simply postulate a private SourceOpen program, generic obfuscation, ideal release oracle, invented OTS label, or a weaker relation.

The original three independent OR challenges, strict contextual modern AuxPoW chain-ID/exact canonical SYS tag, actual claim-prefix ancestor/history/depth qualification, typed malformed carrier/burn proof, same-claim safe native signature, R225 activation binding, and preauthorization/erasure/multi-capsule obligations remain unsolved by this tensor exercise.

## Reproducibility / exact boundaries

Local standard-library CPython scripts were actually invoked twice each, not committed with this note:

  check.py SHA256 d190a9c5a1364d20eeae5bfa5c36953a052d980d7187cb262e1d4319f11f7538
  paired output SHA256 5b84c6fb5007f551eabe5df4a79b8045853a31044b0b277a792460bbc39d80e7
  unary_coupling.py SHA256 48a6a3248d8fa2487f92cb99d14388565ed047a00a8fd3e8a65f54489d839553
  paired output SHA256 3f5931a98f56984e0bce61d1908fcbb5f9cf1a85f7dcaad54d20daac155b1c6a

Complete local derivation, executable sources, four captured JSON outputs and provenance: /mnt/data/R365_global_tensor_cover_20261118.tar.gz (SHA256 8860527fac8457fb5d567034f9514400ce37b87619a854cd08b56c658bce58e3). That archive is LOCAL ONLY and must not be assumed to persist in later executions. Only this note is intended for the PVUGC research branch.

NONQUALIFYING. No progress notification or PR comment; no production changes, merges, deployments, Core edits or automation changes.
