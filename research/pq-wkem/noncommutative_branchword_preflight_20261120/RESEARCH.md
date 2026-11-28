# NCBP — noncommutative branch-product preflight (NONQUALIFYING)

## Continuity and explicit new mechanism

Observed draft PVUGC PR #1 at 3878bac0a3a12d2e55aab932c796e8f75b3c4a1f on research/pq-wkem-validation-20260918; read latest OPT-VK and immediate OTP notes. Narrow recent comment query was empty. No web, new Core code claims, network data, Bitcoin signatures, real original source certificates, FE or quantum experiments.

OTP/OPT-VK required a public polynomial-size source-dependent evaluator that escapes publicly navigable **polynomial state** exploration and signature-VK terminal scans. This pass tests a mathematically different representation: randomized noncommutative product of branch operators. It can have exponentially many distinct path products with only polynomial serialized rows. It avoids the direct BFS premise and additive low-degree coefficient attack, but the *entire public algebra* must be secure.

## Actual classical Build/Open and derivation

For an efficiently represented finite group G, a public length-L known Boolean branch word g_i(b), and a nonidentity target c such that full accepted words have product c and rejected words product identity, sample independent secret gauges U_0,...,U_L. Publish both rows

    B_i(b)=U_(i-1)^(-1) g_i(b) U_i

and D=S XOR SHA256(domain || serialize(Tc)), where Tc=U_0^-1 c U_L.
Public Open on input w computes P(w)=product B_i(w_i) and returns D XOR SHA256(domain||serialize(P(w))). It yields the same frozen S for **every** accepted w; Build and Open have polynomial time and encoding size O(Ln log n) when G is a degree-n permutation group. It uses no table of all future witnesses. It is, however, **insecure**.

For any i, put G0_(i-1)=product_(j<i)g_j(0), P_(i-1)=product_(j<i)B_j(0), and define public

    Q_i=P_(i-1)*B_i(1)*B_i(0)^-1*P_(i-1)^-1
       =U_0^-1 D_i U_0,
    D_i=G0_(i-1)*g_i(1)*g_i(0)^-1*G0_(i-1)^-1.

These publicly exposed Q_i are all conjugates under one shared hidden gauge. This is a full-public cross-occurrence invariant, not an honest-Open query.

## Exact FALSE public-secret extraction

Let a,b be noncommuting elements, c=[a,b]=a*b*a^-1*b^-1, and use one and the **same** Boolean input x in the word

    g1(x)=a^x; g2(x)=b^(1-x);
    g3(x)=a^(-x); g4(x)=b^(-(1-x)).

The complete accepted relation is FALSE: for x=0 or 1 the product is identity, never c. Yet the public conjugate ratios satisfy Q1=U0^-1 a U0 and Q4=U0^-1 b U0, while all-zero public row product P4=U0^-1 U4. Therefore the observer directly computes

    Tc=[Q1,Q4]*P4,
    S=D XOR SHA256(domain||serialize(Tc)).

**This attack is deterministic, involves no accepted witness and uses no secret gauge or group-conjugacy solving**, even when the permutation group size is increased. The entire joint public FALSE transcript leaks the frozen payload, so no full-public FALSE simulator can hide independent candidate S values in this construction. It is a classical attack and thus also an allowed QPT attack; it requires neither SHA inversion nor QROM programming.

## Repair analysis

Making the group large, concealing the gauges, or conjecturing hard conjugacy does not remove the explicit public commutator above. For a different target c not expressible as a short word in Q_i, a second recovery remains: the known D_i and public Q_i give simultaneous conjugacy. If known D_i act transitively on n letters, choose one of n images of a starting point and propagate all colored permutation edges; this finds at most n possible U0 in polynomial time. Reconstruct U_L=(G0_L)^-1 U0 P_L; a public native VK can filter resulting signature candidates. Actual fixture had one candidate at n=5,17,67, but that uniqueness is not a universal theorem.

Replacing operators with secret-key SHA permutations while preserving public composition requires an **actual serialized** one-way, publicly composable hidden-function representation. Plain hash digests do not supply group composition or secret-gauge inverses; publishing SHA keys would expose them. No independently instantiated repair was obtained. Retire this class rather than continuing basis, degree, size or obfuscation experiments. The result does not rule out all specialized hash-only witness encryption, nor instantiate original SHA/AuxPoW.

## Executed reproducibility and exact scope

Standard-library Python checker (source included) was executed twice with byte-identical output on n=5,17,67; TRUE x AND y and FALSE x AND NOT x. It used actual SHA256 over group elements to mask a deterministic synthetic 32-byte payload. Each FALSE prescribed opening rejects, while direct public commutator recovers S; TRUE prescribed opening works for the one accepted input. Its gauge-recovery algorithm uses only public branch rows, and the output counts report one consistent conjugator for each fixture. There was no Bitcoin VM/signature test, native source evidence, FE algorithm, network work measurement or quantum analysis. The deterministic PRNG is **not** security randomness.

    Local executed checker SHA256: 1bdbb8da80e48b8c5c0797980fb13e3e425ff34f4b24f30ed966add534c124f7
    Captured run1 SHA256:          be310b9b35543f9d3730581c4baf6679bc0629c3d970b64af165a8e899a60af7
    Captured run2 SHA256:          be310b9b35543f9d3730581c4baf6679bc0629c3d970b64af165a8e899a60af7
    Local complete derivation SHA256: 7e234eb22a3914e77ee9a651520bed8f5e6f16b419d18cd74458616f199d0dc3

## Unfinished ORIGINAL obligation

Still missing: classical-PPT serialized Build_inc(x_W,S)->C / public Open_inc(C,w)=S for **every** ORIGINAL authenticated and relevant witness, preserving each independent BTC-more-work, finite burn invalidity and strict-contextual Syscoin history/tag-fault OR ground. Source qualification must **cryptographically control release**, bind claim/outpoint/recipient/amount/anchors/depth/deadline/reset/native VK/capsule, and give full-public FALSE/hard-TRUE arbitrary QPT recovery/native-forgery -> actual ORIGINAL certificate or independently grounded hash/native break, including sibling-capsule and malicious setup/source correlations. Native one-honest setup and R225 message binding remain obligations. This is nonqualifying, not a breakthrough, and warrants neither user notice nor a PR progress comment.
