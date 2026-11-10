# R203 — Merkle-anchored SHA source-normalizer attempt (intermediate checkpoint)

Status: unfinished hypothesis, NOT a result or key-release claim.

Repo syscoin/PVUGC PR #1; start branch research/pq-wkem-validation-20260918 at 7b159e6dad80fdc477504ca74eaf1e9ea445b74d, tree c24a6f860f3654aeb13a413f2d3ac70fe1c17f23. R202 immediate predecessor at the same head was read (blob 248a4b1d48e51907a6af873bcad92221a0004f8b). No web or unrelated repos.

**Chosen unfinished question.** Can an authenticated source proof supply a common hidden pad that was fixed before future qualifying PoW, burn-nonmembership, or Syscoin fork evidence became available? Test a Merkle-Anchored Source Hash (MASH) latch, not an arbitrary independent hash puzzle.

One candidate source normalizer derives the known committed Merkle/Syscoin state root (or tagged-ancestor root) from the *actual witness path*: g_x(w)=RootFromProof(w), then proposes

    C=(x,E), E = sigma_cancel XOR SHA256("pad" || g_x(w)).
    Open(C,w) = E XOR SHA256("pad" || RootFromProof(w)).

If g_x(w) is the already public authenticated root rho_x for every accepted witness, Build knows it, but a raw attacker can input rho_x directly or synthetic path material. A repair attempt instead includes witness-specific private input t(w) in g, hoping PoW or actual source ancestry makes it hard to fake. That may lose SAME-capability correctness across different qualified source histories. Distinguish the locally authenticated root computation from full BTC/SYS authentication and from an NP verifier's return Boolean. Do not treat a post-hoc checker as access control.

**Exact experiment to perform** (not yet executed at checkpoint): create domain-separated hash-Merkle path examples with two distinct admissible witness paths sharing a fixed authentic root; compare three pad choices: (i) public-root normalization, (ii) witness-dependent path entropy, (iii) source-extractor root with a verifier boolean. Exercise raw attacks that bypass verifier code and honest openings with distinct qualified witnesses. Then attempt a repair explicitly using the actual SHA path constraints and source binding, or record the exact missing cross-witness equation. Full-public QPT security, current chain validation and source authentication are not claimed.

All actual scripts/outputs must be added only if executed, with exact provenance; preserve research within research/pq-wkem/. No ordinary PR comment for a failed attempt.
