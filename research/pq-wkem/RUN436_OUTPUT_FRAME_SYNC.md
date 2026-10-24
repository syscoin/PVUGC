# Run 436 — output-frame synchronization from replicated finite-alphabet noisy public evaluations

**Scoped classical negative theorem; NOT a PQ witness-KEM construction.**

Live dependency: syscoin/PVUGC#1, draft research branch starting at 5438e05013be585358b03c06c7811c24a080c498. Exact Run 435 note SHA-1 50faa1e8d34ce8022b496d70a954a9d2a673d450. Latest substantive PR comment 6067040320.

## Question
Run 435's multi-view majority attack required publicly aligned output labels. Can each view protect itself by using a separate hidden output permutation? **Not when the inputs are aligned and a polynomial-sized, sufficiently frequent set of output symbols is publicly sampled.** The attacker can estimate each relative frame from joint observations and then apply Run 435's majority step.

## Exact classical-PPT model and theorem
Let X be a publicly enumerable input set of size M=poly(lambda), Y=[m], 2<=m=poly(lambda), and F:X→Y any **balanced** map with exactly M/m preimages per output. Let r=poly(lambda). Honest setup independently samples **static** categorical errors for every input x and view j: the true F(x) survives with probability a=1-p and otherwise is replaced uniformly among the other m-1 outputs, each with probability b=p/(m-1). Errors are independent over pairs (j,x). Any hidden output permutations V_j∈S_m are allowed, even adversarially fixed. The public deterministic evaluators are G_j(x)=V_j(N_{j,x}). The output is *not* an online randomized oracle; the polynomial-sized truth tables can be produced by classical PPT.

For j>0 form public counts C_j(u,v)=#{x:G_0(x)=u and G_j(x)=v}. The true relative label match is v*=V_j(V_0^{-1}(u)). Averaging the two independent symmetric noise channels across the balanced F yields

E[C_j(u,v*)]/M = [a²+(m−1)b²]/m;
E[C_j(u,v)]/M = [2ab+(m−2)b²]/m for every v≠v*.

Their gap is Δ=(a−b)²/m>0 (for 0<=p<1/2). Distinct x contribute independent variables in [-1,1] to C_j(u,v*)−C_j(u,v); Hoeffding and union bound show that every argmax_v C_j(u,v) finds the correct relative frame except with probability

ε_frame ≤ (r−1)m(m−1)exp(−MΔ²/2).

After normalizing each public view with the recovered relative permutation, the per-input correct labels agree in the reference frame V_0 with independent failure probability p<1/2. Majority/plurality over r views gives the full table V_0∘F except with probability

ε_value ≤ M exp(−2r(1/2−p)²).

Therefore the **whole balanced source function is recovered up to ONE global output permutation** by a classical polynomial-time algorithm, with probability at least 1−ε_frame−ε_value. No original NP witness, hidden frame, quantum oracle, global canonical source, or additional crypto assumption is needed.

For m=2, p=1/4, M=4096, r=160: Δ=1/8; ε_frame=4.0272×10^-12, ε_value=8.44249×10^-6, sum <8.45×10^-6. Each view can independently have quarter-rate static noise; no single view needs to be exactly correct.

## Diagnostic and limits
The **exact executed** JavaScript checker, published beside this note, passes 8,515 assertions on 4,096 balanced binary source inputs across 160 independently output-permuted, quarter-corrupted views. It recovers every view's unknown relative permutation and the complete source up to one global swap, including 256 embedded diagnostic key bits up to orientation. A public verification/checking key can distinguish the two orientations. An independent local Python checker with exact rational channel calculations passes 5,672 assertions, and a local Ed25519 diagnostic verifies a signature with the recovered seed; Ed25519 is NOT PQ. This toy's ORIGINAL relation has NO witness; it is a negative control, not all-witness correctness or secure KEM.

Attack taxonomy: (1) seam/gauge correlation from same-input paired views; (2) relative output frames learned but global frame survives; (3) balanced outputs evade simple single-view fiber-spectrum fingerprints; (4) repeated same-source capsules essential; (5) static public chosen-input evaluations enumerated without adaptivity; (6) malicious or correlated noise not covered; (7) cross-context reuse only if same source and aligned inputs; (8) public checking-key resolves binary global orientation in the negative control; (9) attack is classical PPT and hence also an allowed QPT attack, not a distinct quantum-only result.

**Scope exclusions:** Exponentially large output alphabets destroy the polynomial bound; no automatic extension to Simon two-to-one functions over exponentially large domains, reversible permutations with unique output per input, separately hidden input frames, or mutually unrelated relation/UTXO programs. This theorem does not refute CCMR/RIO, does not provide local WE, and makes no PQ security inference. Reference: Canetti–Chamon–Mucciolo–Ruckenstein, ePrint 2024/006, local reversible mixing with much stronger conditional program-obfuscation goals. Full paper proof body not newly audited here.

Run 259 ORIGINAL-source binding does not help: the attack need not present a complete accepted source representation. Run 428's centrally samplable general-NP witness-encryption-strength lower bound and Run 433's native-forgery-vs-full-key distinction remain applicable.

**Still UNPROVED:** all valid ORIGINAL witnesses release the SAME native capability; complete-public-output false-instance QPT native-forgery hiding; unauthorized true-instance signature→ORIGINAL extraction or independent QPT break; malicious N-of-N erasure/abort security; arbitrary multi-capsule composition; practical 128-bit release compiler; conditional Bitcoin P2MR/native-SLH endpoint. No production or Bitcoin changes.
