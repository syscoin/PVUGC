# Run 641 — Genuine SOURCE 2-adic residue inverse-norm obstruction

2026-10-19, draft research only, syscoin/PVUGC#1. Starting SHA dc70382508f395be9ea357f7c19ef5d1ba89d07c.

**Imported premise:** A07 of the October 18 GPT_PRO_WE_REVIEW_PACKET.md gives TV((W,D mod r),(W,U_r))<=delta_slice(r) for the genuine concatenated two-branch Gaussian SOURCE transition D (m by t=2m), q=2^k and r=2^a|q. U_r is uniform modulo r and independent of admissible W. delta_slice(r)=Nt delta_E(r)+t epsilon/(1-epsilon)+beta_bad+eta_impl, with delta_E(r)<=exp(-pi*(s_E/r)^2)/(1-exp(-pi*(s_E/r)^2)). Sufficient *asymptotic* width conditions include s_D/r>=max(8,lambda), s_E/r>=sqrt(lambda), plus full-rank-current-key and actual Gaussian fiber smoothing. W can retain boundary and later transition data but cannot reveal current errors or quotients. No full-q-uniformity or quantum-correlated setup is assumed.

**Theorem.** Let F_t(R) be the number of integer z in Z^t with ||z||_2^2<=R and some odd coordinate. The following holds under the actual A07 premise:
Pr_actual[exists j,z: ||z||_2^2<=R and Dz=e_j mod q] <= min(1,delta_slice(r)+m F_t(R)/r^m).
Proof: reduce modulo r. A solution to a unit target must have an odd coordinate. For any such fixed z, uniform U_r maps it to each e_j with probability r^(-m), since an odd coordinate is a unit in Z_(2^a). Union bound over z and m targets, then pay total variation. On the complement EVERY integer J with DJ=I_m modulo q satisfies ||J||_op^2>=R+1 and ||J||_F^2>=m(R+1); each column J e_j has integer squared norm at least R+1.

For every u>0, F_t(R)<=exp(uR)*theta(u)^t, theta(u)=sum_Z exp(-u z^2)<=1+sqrt(pi/u). Taking r>=16, R=floor(mr/32), u=32/r, t=2m yields
Pr_actual[short column] <= delta_slice(r)+m*kappa(r)^m,
kappa(r)=e*(sqrt(pi/32)+1/sqrt(r))^2<=kappa(16)=0.8626169394<1.
Thus on the good residue event every modular right inverse has norm_op=Omega(sqrt(mr)), norm_F=Omega(m sqrt(r)), improving the parity-only floors of Run 640 for growing admissible r. This is an information-theoretic existence restriction, not an inverse-finding algorithm.

**Conditional proof-budget impact.** Run 638 requires (sigma_G/s_F)^2||J||_op^2<1, impossible on the good event if (s_F/sigma_G)^2<=R+1. The packet A11 noisy retained-image certificate requires ||J||_F<=K_required=eta*s_F/sqrt(pi*r_T*v_G/2), impossible if K_required^2<m(R+1). These exclude only these sufficient reconstruction certificates, not arbitrary SOURCE WE or other simulators; permitted boundary width may be superpolynomial.

**Non-certified illustration:** lambda=N=k=128, m=32768, s_E=512, s_D=32768 meet the displayed A07 width *ratios* for r=32 (not r=64); R=32768, kappa(32)=0.6529398200; the uniform-reference term m*kappa^m<2^(-20136.6), while actual SOURCE failure remains delta_slice(32)+that term. Any inverse on the good event has norm_op>=181.02, norm_F>=32768.50. Actual beta_bad, implementation, full permitted width hierarchy and practical security are NOT certified.

**Checks and model:** Executed standard-library checker compiled and repeated byte-identically, 331 assertions across exact small uniform Z_(2^a) matrices, short integer ball counts, Chernoff theta, and analytic kappa. No Gaussian SOURCE sampler or cryptographic security test. Honest classical setup under A07, arbitrary QPT adversary with public package/checking keys; nonexistence is information-theoretic but arbitrary quantum-correlated advice and malicious setup do not inherit A07. Multi-capsule composition needs separate conditional bounds. Run 259 covers only accepted complete representations -> ORIGINAL witnesses; key/native forgery -> representation is still missing.

**Handoff:** Instantiate largest genuinely certified r, delta_slice(r), s_F/sigma_G, K_required, and all correctness constraints. Full-view false-instance QPT hiding, unauthorized hard-true recovery/forgery -> ORIGINAL extraction, one-honest N-of-N setup, multi-capsule security, practical 128-bit parameters and PQ Bitcoin endpoint are unproved. No WKEM complete. Production unchanged; draft PR and automation remain open.