# R189 — Source-independent evidence cannot evaluate the hidden affine share (intermediate)

Status: mathematical construction/repair attempt in progress, NOT a secure bridge release and NOT a breakthrough. Target exact missing operation from R188: public, noninteractive `EvalSourceShare(C,w)` for an authenticated future R3 AuxPoW witness, returning the setup-hidden affine evaluation needed to recover one frozen cancellation signature. This checkpoint deliberately precedes local verification. No independent experiment results are yet claimed.

## Exact starting context
PVUGC #1, branch research/pq-wkem-validation-20260918, observed head d3d6a2e23d161899a564c25e9222d48a8673a9df, draft/open/unmerged. Read the R188 RESEARCH.md at that head and R187 fixed-root witness uniqueness for the exact predecessor. Latest PR comment query since 2026-11-09T23:00Z gave [] (tool read). No web/literature/other repositories.

## Candidate and first lemma target
R188's f(z)=K+a*z over F_p, baseline z0 != 0, s0=K+a*z0, distinct valid fork z != z0, reconstruction K=(z*s0-z0*s(z))/(z-z0). The formula is correct when s(z) is supplied. Need Build to permit public evaluation s(z) from actual authenticated AuxPoW evidence w with z=z(w), without leak for arbitrary fabricated source w, source-retained secret or online issuer.

Test restricted candidate: C contains s0 and public source-manifest/roots independent of hidden (K,a) conditional on s0. In an ideal target source experiment w and z(w) are sampled/selected from authenticated BTC/SYS history using only public C; source generation has no access to private setup coins and retains no secret coefficient. Investigate conditional distribution of s(z) given (C,w). Does genuine source validity itself correlate its public evidence with hidden affine slope? If not, any public evaluator lacks information even when w valid. Prove precise bound, then attempt to add a minimal setup-created correlation in C without publishing a or K or a per-future-witness table.

Potential caveats to resolve: (1) CK=H_check(K), encrypted signature D= sigma xor H_pad(K), and other public key-correlated checks are NOT independent of K and cannot be silently omitted from a full-public theorem; (2) adversarial source w can depend on public C, but not private setup randomness; (3) baseline source and child outcome may be related, yet both are external to setup's hidden slope; (4) any successful new C correlation must support all 3 challenge branches and QPT simulator, not only the affine identity.

This note is a hypothesis checkpoint. Next: exact finite-field enumerations (small fields only), failure/repair attempts, a scoped mathematical proof and reproducible checker, and preserve final work. No claims of an instantiated release.
