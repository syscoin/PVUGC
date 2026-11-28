# R235 intermediate — frozen hash-pad versus multiple unknown authenticated futures

Run 2026-11-11. Initial observed syscoin/PVUGC PR #1 head 9b3776f4f1bbd34f2c386bc7337feef0573df292, branch research/pq-wkem-validation-20260918. Read R234 research at blob 10f5765efa07f6e8c0a10d1586d1b96def97090a; most recent relevant ordinary comment R225. Offline, hash-only.

**Named candidate:** Source-transcript single-pad gate. One honest setup party freezes a claim-scoped native cancel signature sigma and chooses E = sigma XOR SHA256("pad" || Enc(source future certificate)). Could every later ORIGINAL fork/absent-burn/more-work witness open the identical sigma?

**Necessary equation:** For fixed E,sigma and two qualifying witnesses w0,w1, H(Enc(w0)) = H(Enc(w1)). If the ordered source transcript encodings differ, correct opening under a full-transcript hash requires a hash collision. Separate Bitcoin parent work certificates for the same Syscoin child can differ, and qualifying future source histories may also differ. One fixed-row transcript SHA pad cannot cover all such witnesses without collapsing that diversity.

**Repair hypothesis:** Use a common anchored prefix to ensure equality. It is public before a fault and therefore discloses the pad early. A telescoping hash trace can be zero for every consistent computation, but a public zero can be evaluated without an authenticated source fault. Test exact SHA256d toy work certificates and this algebra, then try a source-certified hidden common label which honest Build can precommit but which future source evidence reveals without a retained miner secret or online authority.

All tests in this checkpoint are pending. No original source verifier, public Build/Open, quantum proof or independent security advance is asserted.