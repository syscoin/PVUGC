# R177 checkpoint 2 — Claim-relevant prefix repairs the one-sided-fork gap

**Candidate positive source-relation reduction, to be verified with exhaustive synthetic boundary checks; NOT a secret-release construction or a deployed consensus claim.** This checkpoint corrects our earlier broad two-sided requirement ONLY for a narrower, claim-relevant fork policy. It does not invalidate R176's need for two later observations when arbitrary future forks must be challenged.

Define `h_rel` as the LAST Syscoin height whose authenticated history/state affects this exact withdrawal (burn, authorization, source-root dependencies and any claimed finality/interval commitment). Fix in `x_W` a fully qualified baseline branch A with child at `n_A` and tag at `t_A=t(n_A)=10 floor((n_A-6)/10)` so that `t_A>=h_rel`. A sufficient minimum is

    n_A >= n_baseline(h_rel) := 10 ceil(h_rel/10)+6.

Let B be any independently qualified challenger history sharing the genuine anchor before its first distinct Syscoin child d, with `d<=h_rel`, valid descendant depth k_LC and a source child at `n_B>=n_first_tag(d)=10 ceil(d/10)+6` whose tag reports B's own ancestor at `t_B>=d`. Then `min(t_A,t_B)>=d`, hence both actual branch ancestor hashes at that common height are unequal unless the child hash commits collide. Therefore *the one fixed baseline tag plus the alternate complete authenticated branch is sufficient* for this **claim-relevant, tag-visible** fork predicate. A two-later-branch relation is not necessary for this narrower claim-specific challenge.

Proof obligation / necessary guard: Since `t_A` rounds UP to a 10-block reference height beyond h_rel, a fork at `h_rel<d<=t_A` may produce a tag difference but DOES NOT change the claim-bound prefix. Check first divergence d from complete authenticated linked histories and require `d<=h_rel`. If the intended protocol deliberately cancels for ANY future Syscoin fork (including after h_rel), retain the two-later-observation R176 relation instead. One cannot silently equate these policies.

This reduces future key-release witness complexity to one new authenticated B history relative to a fixed, sufficiently advanced baseline, for a specifically claim-relevant source-fork challenge. It does NOT generate a precommitted hidden source token, solve hash-only witness encryption, close QPT security, prove original Bitcoin inclusion, or handle malicious cancellation capsules. Actual test and exact outputs follow.
