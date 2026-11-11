# R230: Source-work-derived common token hypothesis (intermediate)

Observed PR #1 head at start: `663d96b99d3d15327b925776786ba48f454dbcc8`, branch `research/pq-wkem-validation-20260918`. Relevant exact-version R229 (blob 6c65d78be1fb624589eb06c5c58699c46e433ef1), R227 (3bef7943c233ff04ae020ebabfa1f2d7272ab308), R226 (685f4371f781cf45d8c31f57d44d1b831d85a8c3) read. Latest relevant ordinary PR comment set fetched. No web/literature.

**Goal:** Test whether *actual SHA256d work-output regularity* provides a setup-predictable, not publicly guessable common decryption token across ALL qualifying AuxPoW fork certificates. Rather than adding invented source OTS labels, derive the pad from a real-style double-SHA parent header whose coinbase commits to a distinct Syscoin child and a tag.

Candidate A: native signature sigma is sealed as D=sigma XOR H_pad(S), with S=SHA256d(parent_header), where the parent passes a target and is authenticated as a relevant AuxPoW source. For EVERY valid alternate source certificate the opener knows S from the parent. Build does not know future parent header. Exact unfinished question: can S be mapped to a single hidden token t available to Build at preauthorization and to every legitimate challenger, but unavailable to adversaries with no ORIGINAL source evidence?

Candidate B: map each S to its forced zero prefix (due to work target) and seal with prefix hash. Then all legitimate work certificates converge, but the prefix may be known from the public difficulty target. Test the convergence/secrecy conflict precisely rather than treating PoW success as a secret input.

Candidate C: bind pad to a source child identity/tag and an authenticated common ancestor rather than parent WorkID, avoiding false forks from parent-work variants. Test whether different legitimate fork child outcomes can still share any *unknown* common value, given claim-prefix anchor and source public inputs.

Test two different legitimately mined toy parent headers (each commits to a different child at same source slot), one work-wrapper variant of the same child, and one privately fabricated child. The fixture is explicitly NOT a real Bitcoin/Syscoin verifier: simplified coinbase bytes and non-consensus easy target. The decisive tests are token equality, public derivability without a witness, and future-header unpredictability to Build. Preserve full mathematical scope and no unproved claim about generic WE or QPT from such tests.
