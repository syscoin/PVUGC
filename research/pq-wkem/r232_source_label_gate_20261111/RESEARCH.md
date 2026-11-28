# R232 — Hash-garbled ORIGINAL source verifier and native-signature security split

**Nonconstructive construction attempt, with a conditional native-authenticity lemma only.** This is NOT a hash-based ORIGINAL witness-KEM, native SLH/QPT proof, deployed Bitcoin or Syscoin consensus test, or a positive report threshold event. Source-conditioned public input-label transfer and a complete public simulation are NOT instantiated.

## Continuity, input and actual actions

Repository syscoin/PVUGC, PR #1, research/pq-wkem-validation-20260918. Starting head 4c7853f2a47433a6a5635b999a72318310c6d377, tree 66d5bd2615b3adadcee0b61886efb51c487bd416. Exact R231 note read at blob c5f09c0375f5b4943f4dd84df4d5bec781689194. Latest ordinary comments since 2026-11-11T15:00Z returned none. An intermediate hypothesis checkpoint was written and attached as commit 43900da1ac5656a8d999fb54faf6dc2ccbbcc4b2 BEFORE experiments. No web, external literature, independent agent, production change or actual native/QPT evaluation was used.

Local /mnt/data/r232_source_label_gate_20261111/checker.py was executed twice: 245 deterministic functional checks with byte-identical captured.json/rerun.json. SHA256 source e1caa5fb3dad0b7ea63132e9c3f849ac0a90ff6f85166908ebc3adaac0f3d131; captured SHA256 fb2e27688b8d4434cff8b75cd1e044b5600edaaac3a2d12ae3ca91948e554f19. These full files are LOCAL ONLY and ephemeral. A separately executed compact reproduction is included at reproduce.py, with 37 checks and the captured output in reproduce_output.json. These fixtures do NOT have actual BTC headers/PoW, Syscoin tags or quantum tests.

## ORIGINAL statement and exact Build/Open objective

For a preauthorized N-of-N vault slot with one-notary activation and anyone-challenge, the immutable x includes exact vault/claim/UTXO and cancel message, activation authentication, source state and anchoring/windows, the native VKs, capsule ID and context. The challenge condition is the union of (1) qualified heavier incompatible Bitcoin work, (2) finite authenticated refutation/nonmembership of the exact required burn, or (3) qualified Syscoin ancestor-prefix fork/tag inconsistency with LC depth and anchoring. An accepted source witness is the FULL actual certificate; a forged tiny hash, invented label or post-hoc successful verifier is not equivalent.

Every setup participant's honest frozen native cancellation signature sigma_i must be recoverable from ANY qualifying ORIGINAL challenge, including later permitted activations, while a full public QPT adversary cannot obtain it prematurely. N-of-N protects the final transaction graph only if at least one honest contribution remains sealed; it does not implement the sealing. The release must be bound to a safe cancellation path, not a bearer private key for unrestricted withdrawal.

## Named candidate: SHA-garbled source-verifier release

Try building a public garbled Boolean verification circuit V_x(w) that verifies entire actual BTC/AuxPoW/PoB/header/ancestor/interval evidence and produces a frozen sigma_i on output 1. Its hash-only gate rows are schematically

    T_{g,a,b} = L_{g,out, f_g(a,b)}
                  XOR H_gate(ctx,g,L_{g,in1,a},L_{g,in2,b}).

The public evaluator must obtain EXACTLY ONE correct input label per witness bit, including globally consistent fanout, from the actual authenticated certificate w. All valid w should lead to the SAME sigma_i; no invalid w or mixed labels should reveal a valid final sigma_i. Neither standard gate garbling alone nor the local checks proves this end-to-end condition, especially against coherent QPT attack.

The unresolved source-native input interface must achieve

    E_x(C,w)_j = L_{j, w_j}

for all ORIGINAL valid w, with polynomial classical setup and evaluation. These preinstalled L values must not be freely obtainable for a contradictory assignment without obtaining an ORIGINAL certified source witness. There is no assumption that a miner, notary, or on-chain record publishes an extra Lamport preimage family.

### Three attempted label deliveries and exact outcomes

1. Public anchor labels L_{j,b}=H(ctx,anchor,j,b). The anchor and j,b are public, so everyone computes BOTH 0/1 labels without original evidence. A single Boolean variable used twice in V can be switched across occurrences, bypassing global witness consistency and reaching a true output for an unsatisfiable local constraint. The local garbled NOT/AND fixture explicitly does this for z AND NOT z; the compact reproduction demonstrates the raw bypass. This is a regression of the already known occurrence-mixing attack, not a new source result.
2. Setup-secret labels L_{j,b}=H(ctx,s,j,b). Build can construct gate rows, but an unrelated public Syscoin/BTC certificate does not reveal s or these labels. Public opening fails without a secret issuer, which the architecture prohibits. Publishing s restores case 1.
3. Future-work-dependent labels L_{j,b}=H(ctx,workDigest(w),j,b). The authenticated future work digest is not known when the vault's gate rows are frozen. Setup cannot install matching gate rows for every future qualifying history; a different digest changes the label and makes evaluation fail. Preselecting finite digest rows gives exactly the coverage issue recorded by R231. This does not imply a global impossibility of hash-only WE.

**Result:** The actual source-to-private-input-label transfer is an UNINSTANTIATED algorithm, not a proof polish. A constrained PRF or noninteractive OT that simply *assumes* only certified witnesses can obtain these labels would rename the missing witness encryption rather than solve it. The full-public simulator must cover malicious source coins, checking keys/native VKs, related capsules, auxiliary inputs, selective openings and QPT coherent access; none was supplied.

## Separate useful conditional lemma: accepted native N-of-N signature reduction

Fix one honest participant h. Its honest setup produces sigma_h = Sign(sk_h,M) and an ORIGINAL-conditioned capsule C_h. An arbitrary QPT adversary, seeing the entire correlated public view and other corrupt participants' data, outputs a classical N-of-N native cancellation authorization tau_1,...,tau_N on the SAME frozen message M. Assuming the native verifier truly checks each h signature:

  Event A: tau_h == sigma_h. The adversary has recovered the exact frozen honest signature, and this is precisely the leaf-capsule recovery event (subject to the exact auxiliary/multi-capsule experiment).

  Event B: tau_h != sigma_h AND Verify(vk_h,M,tau_h)=1. In a straight-line black-box simulator that obtains sigma_h by querying a signing oracle on M to build C_h, this is a *new valid signature on an ALREADY signed message*. It is a strong unforgeability (SUF-CMA) event, NOT ordinary EUF-CMA in that simulator. This is an upper-bound decomposition, not a theorem that the hypothetical native SLH scheme is SUF.

Thus conditional on a full-joint leaf recovery bound eps_leaf and independently justified QPT SUF-CMA bound eps_suf for the actual native signature algorithm with classical signing queries and an explicitly modeled quantum hash oracle, the final accepted cancellation bound is at most eps_leaf+eps_suf (plus any explicit simulation/statistical gap). Reductions are straight-line; no rewinding or volunteered internal A trace. If there are legitimate alternate accepted signature representations with a publicly checkable canonical core, a separate canonicalization proof could replace SUF; it is NOT asserted for the intended native endpoint.

The local toy Lamport-based signature verifier accepts a one-byte unauthenticated suffix. Given a signature on M, changing only the suffix creates another accepted signature on SAME M; this demonstrates why EUF-CMA does not count Event B. This is NOT a real SLH-DSA vulnerability and does not prove any deployed Bitcoin verification behavior. A native path that ALSO cryptographically enforces the exact precommitted signature bytes could block this mutation, but that on-chain capability is NOT assumed available; in particular there is no assumption of CAT, signature introspection or PQ signature-byte hashlock support.

The lemma is CONDITIONAL on the missing leaf capsule and on a native QPT SUF/canonicality property. It does not reduce the ORIGINAL-dependent Build/Open obligation or justify a progress comment.

## Exact next needed construction

A genuine improvement must specify a classical-PPT public-label transfer from the ACTUAL authenticated SHA/AuxPoW source evidence, and the full-public QPT simulation showing that an arbitrary attacker cannot obtain an accepting output without ORIGINAL evidence or an independent hash/native break. It must allow every valid later source history, not a preselected subset or a normal-form known to Build. Candidate search should include source-dependent *nonlocal* hash correlations rather than repeated direct pads and public source bits. There is no reason to resume packing/compression or switch to lattices. No ordinary PR comment or user progress notification warranted from this pass.

## Bounded run provenance

Full local checker: 245 functional checks, SHA256 e1caa5fb3dad0b7ea63132e9c3f849ac0a90ff6f85166908ebc3adaac0f3d131.
Full local capture: SHA256 fb2e27688b8d4434cff8b75cd1e044b5600edaaac3a2d12ae3ca91948e554f19.
Published compact reproduce.py: SHA256 b5bcdb587ca133249a49e689e4d9217692cfab64749c2555195fe38555a9b11a, 37 functional checks.
Published compact output: SHA256 3f00006f65dc5fae4edef30ace3dc8cf175521b5e07afbcab7cf5b17157ce10b.
All checks are deterministic functional regressions only. No QPT proof, oracle programming, deployed consensus, native signature or actual authenticated source evidence was tested.
