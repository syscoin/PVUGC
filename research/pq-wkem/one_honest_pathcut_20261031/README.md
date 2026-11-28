# One-honest Native Preauthorization Cut (ONPC) — restricted research checkpoint

**Not a generic-NP PQ witness-KEM; not deployable Bitcoin functionality.**

This checkpoint extends the prior restricted uniform-FALSE binary-ISIS/full-public native signing-transcript lemma to an N-of-N preauthorization graph with one honest signer and N−1 corrupt signers. The graph/signature cut condition is proved in an abstract finite spend model, and the restricted full-joint QPT LWE/native-EUF composition is derived under explicitly limited SOURCE, auxiliary, signing-query, and selective-opening distributions.

**Crucial policy:** never pre-sign the future native challenge-path message using the signing key encrypted in the witness capsule. Pre-sign exact safe timeout and safe resolution messages; the challenge must require a fresh native signature recoverable from valid ORIGINAL evidence. Signing bytes must bind every actual consensus-effective outpoint, branch, output, lock, and claim/context field. No real Bitcoin SIGHASH implementation is checked here.

[Complete research, exact checker, captured output and provenance](./ONPC_RESEARCH_AND_CHECKER.tar.gz) (gzip tar containing RESEARCH.md, checker.py, output.json). The bounded Python standard-library model checker passed 681 checks twice with identical output, including counterexamples for five broken controls. It does not implement signatures or test QPT hardness.

Local archive SHA-256: `69c83b2e124f89e085adbe8b53e0bbf5056956bca114aa76c5fd49cb815f816f`.
Expected archive Git blob SHA-1: `50a653f307c0e4299fde8e948fb8cb63d3170131`.

**Still missing:** adversarial FALSE full-public security, hard-TRUE unauthorized native signature/key recovery → ORIGINAL witness or independently justified QPT break, a witness-free generic NP compiler, malicious distributed source setup/abort, full transaction graph coverage, actual native PQ Bitcoin endpoint, and calibrated parameters. The prior chosen-FALSE nonbinary public opener remains a decisive attack on the restricted SOURCE compiler. Keep automation enabled.
