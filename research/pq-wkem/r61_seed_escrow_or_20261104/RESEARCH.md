# R61 — SEED-ESCROW-OR: one globally masked native signature and branch-local LWE root release

**Date:** 2026-11-04. **Status:** restricted constructive release/efficiency advance; NOT a secure generic PQ witness-KEM. Offline, read-only research sources restricted to exact R60, R58 and R52 files on syscoin/PVUGC PR #1. Starting verified PR head: ede83cb5df52af1e38d521250ce61abc56c29888; branch research/pq-wkem-validation-20260918, open/draft/unmerged. Latest substantive ordinary comment: 6628928548. No web/literature search.

## Explicit new algorithm (continuation of R60)

R60 repeats a complete L-bit native signature ciphertext separately in every authorized ORIGINAL OR branch and requires a large public LWE matrix whose output is L bits. R61 places ONE native-signature ciphertext in the OR manifest, and each independent ORIGINAL branch encrypts only a common k0-bit root K using its own LWE key tuple. The root is not a shared branch secret and is not published. The branch source material remains independently sampled; an authorized TRUE opening deliberately releases K and thereby the common signature to the OR path, not the other branch secret tuples.

Preauthorize one ordinary fixed-length native signature sigma* on one exact challenge-path message m* before irreversible funding. The authenticated m* and original statement x bind relation identity, claim/UTXO, actual SYS/BTC authorization/burn/output, branches/anchors/window/interval tags, graph/manifest, challenge authorization policy, native vk and A0/A identifiers. m* is formed from immutable scope fields, NOT the later ciphertexts, thereby avoiding a signature cycle. A separate final authenticated manifest must bind all resulting ciphertexts, SOURCE capsules, CK/Aux and corresponding graph edges before funding; full one-honest N-of-N abort/security composition is still open.

Let lambda be a security parameter, B polynomially many fixed authorized branches, and signature serialization length L bits. Uniform independent public matrices A0 in Z_(2^t0)^(m0 x n0) and A in Z_(2^t1)^(m1 x n1) are honestly sampled. Let k0=n0*t0+m0*b0, m0*t0=2*k0, m1*t1=k0 and 2^d*k0=L. Define S_b={-2^(b-1),...,+2^(b-1)-1} and independently sample all indicated error coordinates uniformly from S_b0 or S_b1. This is a specified ordinary decisional LWE distribution, not a source-opening or witness-encryption assumption.

The R52 base expansion G_A0 parses any k0-bit uniform seed as s0 uniform in Z_(2^t0)^n0 and e0 uniform in S_b0^m0, then serializes A0*s0+e0 modulo 2^t0 to 2*k0 bits. TreeG(A0,K) iterates this binary expansion to depth d using the SAME public A0 at every node, yielding L bits. Classical Build selects K uniform in {0,1}^k0 and publishes:

Dsig = Encode(sigma*) XOR TreeG(A0,K).

For each authorized ORIGINAL branch j, independently choose s_j uniform in Z_(2^t1)^n1, e_j uniform in S_b1^m1, and Kbind_j uniform in {0,1}^kappa. Publish:

Y_j = A*s_j+e_j mod 2^t1;
D_j = K XOR Serialize_t1(Y_j).

Build additionally produces genuine ORIGINAL-NP source capsules for the canonical encoding of ONLY (s_j,e_j,Kbind_j), using the existing R54/R60 projector P_xj, source section, bounded noise eta, and per-word formula Z_(j,u)=P_xj(Delta*mu_(j,u)*1+eta_(j,u)). The current dense source compiler is NOT a polynomial generic-NP implementation and R58 defeats its hard-TRUE secrecy. This change does not purport to fix it.

Define Base=H(canonical(version,x,ctx,manifest,m*,vk,A0,A,Dsig,all ordered (D_j,Z_j),allowed related public capsules)), excluding CK/Aux to avoid cycles. Build sets CK_j=F_Kbind_j("CK",Base,j), Aux_j=F_Kbind_j("AUX",CK_j,Base,j). Any authentication against hostile transcript mutation requires independently justified QPT hash collision resistance/keyed binding; the following fixed authenticated-scope theorem only uses the exact deterministic correlation. The FULL public view includes relation/statement, native verifying key, context, claim/branch manifest, all Dsig/D_j/Z_j/CK_j/Aux_j, and permitted correlated related capsules/openings.

Open(j,w) checks the ACTUAL ORIGINAL R_j(x_j,w)=1 OFF CHAIN and fixed authorized claim/path, evaluates the source section at w, nearest-center decodes all s_j/e_j/Kbind_j and checks CK/Aux. Compute K'=D_j XOR Serialize(A*s_j+e_j), sigma'=Dsig XOR TreeG(A0,K'), and return sigma' only if ordinary native Verify(vk,m*,sigma') accepts. Every valid ORIGINAL witness in ANY authorized branch obtains the SAME K and the SAME precommitted sigma*, with distinct witnesses free to have distinct intermediate evidence. Bitcoin performs no NP verifier, VM, PCP/Kilian or general BitVM proof; the PQ native endpoint remains hypothetical.

## Full joint-view restricted QPT theorem, with actual LWE simulator

Target game: B unopened target branches are publicly certified FALSE with efficient, hybrid-invariant P_xj(1)=0. Honest source-noise tapes are jointly samplable independently of target s/e/K; branch secrets are independent conditional on honestly uniform public A0,A. Native m* is fresh and no target signature is available from a signing oracle. The arbitrary QPT adversary may coherently process the whole CLASSICAL joint transcript and receive polynomial quantum advice independent of target signing secret/root/branch secrets (given the public authorized scope). Independently seeded related TRUE claims may share A0, A and vk, and have adaptive CLASSICAL opening responses on DISTINCT native messages, all simulatable by the reduction. No target/authorized sibling opening, target-correlated private advice, coherent opening-oracle queries, malicious setup, target rebinding, arbitrary-FALSE inputs without certificate, or post-release secrecy after a legitimate OR opening is included.

For every certified-FALSE target source word, P_j(1)=0 implies the exact pointwise identity:

Z_(j,u)=P_j(Delta*mu_(j,u)*1+eta_(j,u))=P_j(eta_(j,u)).

To hybridize branch j, given an ACTUAL ordinary LWE challenge (A,Y) with Y either A*s+e or uniform, the classical PPT simulator samples the common K and every other independent branch, generates challenged Z_j from eta alone WITHOUT s/e or a SourceOpen oracle, samples Kbind_j itself, sets D_j=K XOR Serialize(Y), then computes every secret-Kbind-dependent CK/Aux and related source/opening response AFTER the complete public transcript is fixed. This exactly couples the real target transcript to the real challenge and the next uniform-pad hybrid. There are B hybrids under ONE common public A: loss at most B*Adv_QPT-DLWE_pad.

In the all-uniform target-pad hybrid, all D_j, source Z_j, Kbind_j and independently opened related claims can be generated without K BEFORE applying transcript CK/Aux. Do NOT assert independence conditioned on CK/Aux: CK/Aux may correlate Dsig and D_j. Instead recalculate the entire correlated CK/Aux after EACH subsequent change to Dsig.

Replace TreeG(A0,K) with uniform L bits by R52's explicit level-by-level hybrids, replacing each of the 2^d-1 internal node outputs one by one. A reduction embeds one ordinary QPT decisional-LWE_base challenge (A0,Y) at the chosen node, computes its descendants from Y, generates other nodes and independent related opening histories, and recomputes Dsig, Base, ALL CK/Aux. A0 is shared across all nodes; no fake independently redrawn matrix, SOURCE-opening oracle, quantum rewinding or QROM programming. This costs at most (2^d-1)*Adv_QPT-DLWE_base. Arbitrary coherent quantum processing of the entire resultant classical public data is allowed.

In the final hybrid Dsig is uniformly random and can be sampled without the native target signature; D_j and source capsules are already simulatable without K. A straight-line QPT native EUF-CMA reduction receives vk, does not request a signature for m*, supplies native signatures only for independent related messages, and regards an accepted target-path output as a fresh-message native forgery. For this specific fixed-scope, certified-FALSE experiment:

Pr[QPT attacker obtains an accepted target native signature or recoverable capability] <= B*Adv_QPT-DLWE_pad + (2^d-1)*Adv_QPT-DLWE_base + Adv_QPT-native-EUF-CMA + optional independently justified QPT binding term + negligible unbiased-sampling error.

No uninstantiated common-hidden-value-release, WE/iO/WPRF, SourceOpen, provided internal representation or polynomial-time generic-NP extraction is smuggled into this conditional theorem. There is NO hard-TRUE claim.

## Concrete efficiency and costs (illustrative, NOT QPT-128 validated)

Take R52 base q0=2^16,n0=256,m0=1024,b0=4, giving k0=8192 bits and shared public A0 size 524288 bytes. For a single fixed 8192-byte native signature, d=3 and seven base tree expansions. Choose branch-pad q1=2^16,n1=256,m1=512,b1=4, giving k0=8192 output bits and shared pad A size 262144 bytes.

With B=8, R60 has one 4096x256 16-bit public LWE pad matrix (2097152 bytes) and eight full 8192-byte signature ciphertexts (65536), total 2162688 bytes. R61 has A0 524288 + A 262144 + one Dsig 8192 + eight Dj of 1024 bytes each, total 802816 bytes. **Reduction exactly 1359872 bytes, or 62.8788%, for the enumerated public matrices and ciphertexts ONLY**. Source, CK, aux, graph, vk and evidence are excluded from BOTH totals. SOURCE also carries fewer secret error coordinates per branch but its full sizes are not estimated.

Build modular multiply-add estimate: R60 B*4096*256 = 8388608; R61 B*512*256 + 7*1024*256 = 2883584, 65.625% fewer. Individual Open is SLOWER: R60 4096*256=1048576 vs R61 512*256+7*1024*256=1966080, excluding SOURCE verification. A0 is explicitly paid for, not a free CRS. The dimensions, source and native signer are not production parameters.

## Exact executed checks, provenance, and hard-TRUE obstruction

Exact published CHECKER_MIN.py executed successfully with **10113** finite assertions, 512 genuine two-bit ORIGINAL-witness openings across two distinct TRUE branch relations, 128 certified-FALSE view couplings, and exact public byte arithmetic; OUTPUT_MIN.json contains its exact output. Extended LOCAL-only CHECKER.py executed twice identically with **68108** assertions: 512 genuine ORIGINAL branch openings, 128 full-joint FALSE public-view couplings INCLUDING a separately openable related TRUE claim, 256 genuine related TRUE openings, 128 uniform pad substitutions, 384 internal tree-node LWE-challenge/full-CK-Aux couplings, and exact resource arithmetic. The extended Python checker uses a toy q=16 LWE distribution, finite Boolean relations, synthetic 32-bit signature, and deterministic SHA3/HMAC only as a transcript function. Finite tests establish no QPT hardness, independent PRF security, native SLH correctness or 128-bit strength. Full extended local derivation and reproducible code are separately preserved; only the shorter executed checker is claimed identical to the published blob.

**Next unresolved equation:** For arbitrary hard-TRUE ORIGINAL x and full joint V, show Pr[A_QPT(V) outputs accepted capability] <= Pr[Ext^A outputs an ACTUAL ORIGINAL w satisfying R_original(x,w)=1] + Adv_QPT(independently justified break) + negl(lambda). The R58 public-trace bypass still applies to this TRUE quotient source. R61's new outer seed layer is NOT a repair. Source challenge simulation for hard TRUE, polynomial generic-NP compiler, arbitrary-FALSE security, malicious N-of-N setup/abort/retention, data availability/observation/censorship and hypothetical Bitcoin native no-EC-key-path PQ signatures remain outstanding. Completion criteria unmet; leave existing research automation enabled.
