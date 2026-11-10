# R190 intermediate — source-semantic tag normalization for authenticated fork-release witnesses

Status: substantive ORIGINAL source-validation component, not a secret-release construction, quantum-security theorem, deployed consensus fix or generic WE.

## Exact continuity
syscoin/PVUGC PR #1, draft/open/unmerged, branch research/pq-wkem-validation-20260918. Starting head 435d2cfdffa51b1acae98db2864e24771f7e1f84, commit tree 4e23fca0866ec090be538b5de0d784dee43acdf4. Read R189 exact research (blob bcea14a1ee98f12e4b91a37461efe32c9ad37a98); latest relevant issue comments since 2026-11-10T03:00Z: none. No external literature/web, no independent agent or production change.

## Explicit chosen indispensable subproblem
A proposed public hash-only gate must bind successful raw opening to the ORIGINAL authenticated Syscoin/AuxPoW semantics, not to an attacker-selectable coinbase string. At pinned syscoin/syscoin commit 1180dad257fb3cda797187f51ccc519b684e148d, src/validation.cpp CheckContextualAuxPowTag first finds ONE occurrence of pchSyscoinHeader in each unspendable output, then searches anywhere AFTER that first occurrence for the 36-byte expected ancestor hash+uint32 height. It uses foundSysTag to count distinct outputs having the marker, not marker occurrences within one output. Consequently the exact pinned check appears to accept multiple marker occurrences and conflicting looking tag tuples WITHIN ONE unspendable output, provided the expected tuple appears somewhere after the first marker; source verification still requires all other actual consensus conditions.

A bridge that interprets any marker-looking 36 bytes as a standalone authenticated tag would permit a fabricated inconsistency challenge even where the candidate child ancestry and Core-accepted contextual tag are consistent.

## Candidate normalization
For a source observation P containing a full candidate child chain, authenticated AuxPoW carrier and contextual source position n:
1. Check core-compatible parent coinbase/tag existence and necessary surrounding constraints; it is an existential accepted-tag predicate under this pinned code, not a strict canonical single-tuple decoder.
2. Independently compute the SEMANTIC outcome O(P) = (h_ref(n), GetAncestor(child_branch, h_ref(n)).GetHash()), where h_ref(n)=10*floor((n-6)/10) in the applicable active regime. Do NOT extract O(P) from an unvalidated marker occurrence.
3. Deduplicate observations by actual child-header/ancestor identities: same child under another parent-work certificate is same child outcome. A pair is a fork only when two separately qualified original histories show positive incompatible ancestry and satisfy light-client/window/anchor requirements.
4. If explicit malformed-tag fault policy is desired, define it relative to the consensus-compatible existential tag check, with an independently authenticated outer carrier; otherwise same-output extra marker bytes do not by themselves establish a fault.

This is a proposal for an ORIGINAL semantic precondition inside a future release circuit, NOT a completed crypto gate.

## Planned bounded tests and repair
Emulate the exact pinned marker-scanning control flow over synthetic complete unspendable coinbase script outputs. Test valid single tag, conflicting marker followed by correct marker in same output, reversed order, matching tuple far from first marker, two marker-bearing outputs, missing expected tuple, fake wrong bytes, and identical child with different parent work certificates. Demonstrate a false-positive if raw tag extraction is used as the challenged statement, while semantic child-ancestor normalization rejects that fabricated contradiction. Also derive proof obligations and exact limitations: emulation is not compiled C++ or deployed-chain tests; source include/proof/current consensus must not be asserted by fixture flags.

Next step after normalization: seek an actual polynomial hash-only protected RELEASE encoding that is unlockable by EVERY ORIGINAL challenge witness. An authenticated normalizer only fixes the relation: it does not supply hidden correlated preimages or public Build/Open. No premature claim of a breakthrough or PR progress comment.
