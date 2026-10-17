# Run 548 — anchored boundary leakage in a local reversible release frontier

Starting PR #1 head: `16b3b9235cb1821c7f80ed77d304edb4ffb98c70`; branch `research/pq-wkem-validation-20260918`. Exact Run 547 graph-holonomy, Run 259 source-binding, and the live CLZ applicability files were read. This is a **negative structural result**, not a WKEM.

## 1. Exact anchored-gauge theorem

For a finite permutation group G, an oriented graph with bare transitions T_e, and independently sampled uniform private vertex frames g_v, publish explicit invertible tables A_e=g_head T_e g_tail^{-1}. At anchored vertices B additionally disclose full g_b. Honest setup is classical PPT for efficiently represented permutation families; adversaries may be arbitrary QPT with the entire public view and arbitrary independent auxiliary data.

In a connected component with an anchor r, choose a spanning tree and denote tree transports from r to v by P_v(T), P_v(A), traversing reversed edges by inverses. Then P_v(A)=g_v P_v(T) g_r^{-1}. The following are exactly publicly recoverable:

* For every other anchor b: I_b=g_b^{-1} P_b(A) g_r=P_b(T).
* For every non-tree edge e:u->v: J_e=g_r^{-1} P_v(A)^{-1} A_e P_u(A) g_r=P_v(T)^{-1} T_e P_u(T).

**Theorem.** Two fixed bare-transition families have identical complete joint distributions of tables and exposed anchor frames iff all I_b and J_e agree exactly. Otherwise the distributions have disjoint support. Components without anchors obey Run 547's simultaneous-conjugacy theorem instead.

**Proof.** Each invariant is obtained by telescoping cancellation. Conversely, once anchored g_r and public tree tables are fixed, every unanchored frame is uniquely reconstructed as g_v=P_v(A)g_r P_v(T)^{-1}. Anchor-path constraints ensure the other exposed frames agree; non-tree constraints ensure remaining edges agree. Every realizable public view has exactly one uniform mask tuple and probability |G|^{-|V|}; equal invariants give identical supports/weights and unequal invariants disjoint supports. QED.

## 2. Perfect leakage even on a forest

Take the tree 0->1->2, G=S_3, T_01=I, T_12=S^b where S=(0 1) and b is a hidden bit. Exposing both endpoint full frames gives

g_2^{-1} A_12 A_01 g_0=S^b.

With no anchors or only one endpoint anchor, the joint table distributions are identical. With both anchors, an ordinary classical observer recovers b perfectly. Thus Run 547's cycle-rank-only cut criterion applies only to the table-only unanchored view.

Even **single-state tokens** can suffice: for one edge A=g_1 T_b g_0^{-1}, publish l_in=g_0(0), l_out=g_1(0), with T_0=I, T_1=(0 1). Then A(l_in)=l_out iff b=0. Each of the three two-object marginal distributions (A,l_in), (A,l_out), (l_in,l_out) is identical across b; the complete three-object joint supports are disjoint. No complete endpoint frame is necessary.

## 3. Rooted-forest cut criterion

For a connected graph with cycle rank beta=E-V+1 and a full-frame anchors, the fewest publicly invertible edges that must be removed to eliminate **all cycles AND all paths joining two anchors** is

min_removed = beta + max(0,a-1).

For a=0 use a spanning tree. For a>=1 any admissible forest has at least a components, hence <=V-a edges; a multi-source rooted spanning forest with one anchor per component achieves V-a. Subtract from E; sum separately for disconnected original components. This is an **exact graph-cut statement**, not a cryptographic lower bound on obfuscated gates. Capability-independent invariants might be safe, and even an opaque cut can leak through forward oracle evaluation or partially exposed labels.

## 4. Falsification, QPT status and scope

Two independent deterministic checkers were run twice: exhaustive standard-library Python and separately implemented JavaScript. For S_3, a three-vertex tree has 216 mask assignments per bit, identical table-only and one-anchor distributions, and disjoint two-anchor supports. A single-edge partial-token example has 36 mask assignments per bit; joint supports have sizes 18 and 36 with zero intersection; all three pair marginals coincide. Exhaustive rooted-forest cuts: anchored path 1, anchored diamond 2, unanchored diamond 1, theta graph with three anchors 4. The algebra above proves the general result; finite tests do not establish security.

Attack taxonomy: full-frame path cancellation, global gauge synchronization, joint statistical fingerprinting and public chosen-state evaluation are explicitly broken. One honest capsule suffices, so multiple views, fresh context labels, honest setup and erasure do not repair those concrete attacks. Public checking/output tokens can be anchors. The attacks are classical, hence QPT. No positive QPT theorem, coherent-only attack, security parameter, or malicious-setup construction is claimed. The positive distribution theorem assumes independent uniform hidden masks and excludes correlated auxiliary outputs.

**Composition boundary:** This transparent-table construction is not CLZ's obfuscated forward representation. It provides no ORIGINAL witness admission and no accepted representation within Run 259's rho_x/SrcExt/SIS hypotheses. The unresolved target remains all-valid-ORIGINAL-witness SAME capability, full-public QPT false-instance hiding, unauthorized true-instance recovery or accepted native forgery -> ORIGINAL witness/independent QPT break, malicious N-of-N setup/erasure, multi-capsule safety, practical resources, and conditional native-PQ Bitcoin graph. No new complete primary-literature proof audit was completed. Production unchanged; PR remains draft; stopping condition unmet.
