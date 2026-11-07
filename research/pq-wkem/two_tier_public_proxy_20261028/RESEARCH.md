# Two-tier NP SOURCE: exact/short masking and public-proxy FALSE counterexample

**Outcome: NO POSITIVE SECURE WITNESS-KEM ADVANCE.** One resource-bounded offline continuation of the broken 3CNF-to-LWE syndrome compiler. We tested a concrete alternative that does not reveal the protected digit through public d alone. It obtains exact whole-ciphertext hiding for some certified-false examples and every-original-witness correctness, but a fixed FALSE ORIGINAL 3CNF admits a publicly computed invalid pseudo-moment that decrypts the COMPLETE native seed. Thus arbitrary-false full-public security fails classically, a fortiori for QPT. Do not promote this as a generic-NP construction.

Provenance: syscoin/PVUGC open/draft/unmerged PR #1, branch research/pq-wkem-validation-20260918, start 8a499e490a5a0414690b88029ebc926c39fc7dd8; latest substantive comment 6483757636. Exact predecessor research/pq-wkem/3cnf_syndrome_public_leak_20261028/RESEARCH.md (blob 04c996ab35d43cc8696763825f83578e80120001). Shared LWE selective opening predecessor (blob 8d7c996046bed561c3f95f022412e15f5ae7935b). This is an internal construction check, not internet research.

## Concrete Build and Release

Let q be an odd prime, h<m_L, g=2h+1, radix B=floor(q/g). Encode a 3CNF verifier in squarefree Boolean moments phi_d(W), with one public column for each nonconstant monomial of degree <=d. Construct EXACT rows (A_E,b_E) from clause falsification polynomials f_j(W)=product of negated literals, with zero residual on EVERY ORIGINAL valid W. Construct SHORT rows (A_L,b_L) from two variable rows (e_i,0),(e_i,1) and one signed literal-sum row with b=2-(number of negative literals) for each 3CNF clause. For all valid Boolean W, e_L(W)=b_L-A_L phi_d(W) is ternary. Every supplied accepted short source opening projects to an ORIGINAL Boolean satisfying assignment; supplied-opening soundness alone is insufficient.

For each radix digit a of a precommitted genuine native signing seed (or an independent XOR share of that seed), honest classical Build samples u uniformly in F_q^{m_E} and r uniformly from the signed constant-weight vectors with h distinct nonzero positions and independent fair signs. Publish the COMPLETE source ciphertext:
  c = A_E^T u + A_L^T r  (mod q)
  d = b_E^T u + b_L^T r + g*a (mod q).
The public view includes ORIGINAL relation/statement, capsule, genuine pk(K), full typed claim/path/context, D=U0 XOR XOR_i Z_i, V=K XOR U0, allowed public auxiliary data and any modeled related capsules. Never reuse u or r between columns. Any valid ORIGINAL W computes d-phi_d(W)^T c = g*a + e_L(W)^T r, |e_L(W)^T r|<=h, and cyclic nearest-center decoding returns a. Distinct ORIGINAL witnesses recover ONE SAME precommitted K, with large evidence kept off chain. Bitcoin performs no original NP verification.

For a certified FALSE where there is lambda satisfying A_E^T lambda=0 and b_E^T lambda=1, a->a' is perfectly coupled on the WHOLE (c,d) by u->u+g(a-a')lambda, holding all other randomness fixed. Uniform u preserves the measure. This survives genuinely correlated native checking key/XOR-share metadata, fixed public context, and independent related masks conditional on the coins; the usual proper-subset opening restriction still applies. In the degree-3 FALSE XOR triangle the exact rows have rank 8 and this certificate exists. An extended independent local Python checker verified 1,024 whole-vector couplings, and true related triangle has two valid distinct witnesses decoding the same mock seed. This conditional class is **not all false NP** and says nothing about hard-true soundness.

## Public projection, not d alone

An adversary can efficiently solve public linear equations for ANY z such that A_E z=b_E. It then calculates
  d-z^T c = g*a + (b_L-A_L z)^T r.
If eta=b_L-A_L z has max absolute coefficient D, conditional on the random support of r its signs are independent, giving:
  Pr[wrong digit] <= 2 exp(-h/(2D^2)).
For L columns, entire-key attack failure <=2L exp(-h/(2D^2)).
This is a bound on the ATTACK FAILING, not a security guarantee. z need NOT correspond to ORIGINAL W or even be accepted as a source opening. The uniform exact-row mask vanishes under the PUBLIC projection. No SourceOpen oracle, LWE secret, adversary-volunteered representation, quantum rewinding, native forgery or oracle extraction is needed.

## FALSE ORIGINAL instance with successful public invalid decryptor

Six Boolean variables x0..x5, eleven ordinary 3CNF clauses:
  x2 OR NOT x3 OR NOT x5
  NOT x2 OR NOT x3 OR NOT x5
  x0 OR x1 OR x3
  NOT x1 OR NOT x3 OR x5
  x1 OR NOT x3 OR x5
  NOT x0 OR x2 OR x3
  x1 OR NOT x2 OR x3
  NOT x1 OR NOT x2 OR x3
  x0 OR NOT x1 OR x4
  x3 OR NOT x4 OR x5
  x0 OR NOT x1 OR NOT x5.

All 64 Boolean assignments FAIL the ORIGINAL verifier, as exhaustively checked. At squarefree moment degree d=3, eleven exact clause rows with 41 nonconstant columns do NOT yield an exact anchor shift certificate. Yet public linear algebra with all first moments fixed to zero solves A_E z=b_E with just z[x0*x2]=1 and z[x0*x3]=-1. Verify the equation directly on all eleven public rows. It is NOT any Boolean witness: all first moments are zero but higher moments are nonzero. It is NOT an accepted SOURCE opening either: its short-row residual includes 2, whereas accepted short errors are in {-1,0,1}. Nevertheless every short-row residual has magnitude <=2.

At illustrative q=65537,h=800,g=1601,B=40,m_L=2000 (repeat the 23 short-row types), three masked 256-bit XOR shares occupy 49 radix columns each, L=147. Their PUBLIC source ciphertexts can be projected by the explicit z; conditional sign concentration proves the full signing seed is recovered with probability at least 1-2*147*exp(-800/8), exceeding 1-2^-136.0698. A deterministic offline JavaScript checker accompanying THIS note was executed with multiple complete mock 256-bit FALSE-instance key recoveries. This is a classical PPT false-instance recovery attack on the complete source; adding a genuine pk(K), relation context, or adaptive sibling openings cannot erase information already recovered. Those numeric parameters are illustrative, **not** 128-bit QPT-LWE security estimates, and no native SLH/BTC verifier was implemented.

The extended LOCAL-ONLY Python checker (separate from the exact published JS checker) passed 6,371 assertions on two byte-identical runs, including 1,024 whole-vector certified-false couplings, 8 full 128-bit same-K witness trials, four 256-bit OR3 pseudo-opening trials and four 256-bit recoveries on this FALSE 11-clause statement. Its exact source, output and provenance are in the local research archive; do not imply it was published to GitHub unless separately verified.

## Status and precise handoff

The repair is disqualified. A useful generic compiler must prevent public short-residual proxies for EVERY false ORIGINAL x, AND prove that arbitrary QPT final-key recovery or fresh intended-path native forgery -> actual ORIGINAL witness or an independently justified QPT break. Excluding only supplied accepted representations is insufficient. The remaining exact challenge is to jointly instantiate source setup/opening and the LWE/QPT hybrid without a hidden witness, source oracle, low-degree affine closure, canonical/common preimages or a self-justifying witness-encryption assumption. No extra padding, public basis rotation or scalar LWE wrapping repairs the displayed cancellation. Malicious N-of-N setup/abort/honest erasure and no-bypass graph, pre-funding evidence/DA, actual SYS/BTC headers/AuxPoW/tags/window/ancestor rules and hypothetical PQ-only native Bitcoin endpoint are independent unresolved obligations. Keep the research automation enabled.
