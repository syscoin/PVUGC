# R390 — Useful-completeness quantifiers for one-honest FE setup (nonqualifying)

## Source and candidate
Open draft syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918, starting SHA cb738cab370909ae36b78699b9ffc827051ef0b4 (R389). Read R389 exact RESEARCH.md blob 0c6bd14c514d0188f6a0a3c261f6e553642548d5 and R388 note. Recent issue comments since 2026-11-18 19:24 UTC were empty. No Core source, actual chain, FE implementation, external literature, or network tests were accessed.

R389's public source-path hash-lock gate and R388's noncommutative instructions were already defeated or unimplemented; another graph/degree/hash-pad variant would not change those attacks. This execution investigates an indispensable but *distinct* incomplete setup component of the previously proposed FE covenant: can one honest participant accept N-1 maliciously generated capsules and guarantee every future ORIGINAL witness releases *all* fixed native signature contributions? A proof that a compiler ran correctly does not automatically establish that universally quantified property. It is NOT a solution to the source-release cryptography.

## Exact quantifier
Let W_x={w:R_orig(x,w)=1}. Standard randomized correctness might supply only:
  for each fixed x,S,w in W_x,
    Pr_{rho <- D}[Open(Build(x,S;rho),w)=S] >= 1-epsilon(lambda).
But the frozen, accepted setup requires:
  for each accepted C, for every w in W_x,
    Open(C,w)=S.
These quantifiers are different.

Construction A (one point exception): fix a nonempty witness set W of size M, sample rho uniformly in W, and define an otherwise correctly generated capsule whose evaluator returns S on every w in W except w=rho. For each fixed valid w, failure probability is 1/M, negligible if M is exponential. For *every* sampled capsule, however, there is a valid w=rho that cannot open it. A sound proof of canonical generation truthfully accepts such a capsule. This is an abstract correctness counterexample, deliberately **not** a secure FE/WE system.

Construction B (adversarial coins): make a canonical Build algorithm catastrophically fail for every valid w when rho=0^lambda, and correct for all w otherwise. Uniform independent honest coins produce failure probability 2^-lambda, yet a malicious contributor can choose the zero tape and truthfully prove it followed canonical Build. Witness-existence/ZK of the deterministic Build equations cannot attest to randomness provenance.

## Restricted repair, with precise boundary
For a family of capsules define bad-set B(C)={w in W:Open(C,w)!=S}. A k-capsule *accept-any* release wrapper is universally correct iff the intersection of all B(C_i) is empty. For the extremely restricted one-excluded-point construction, two distinct excluded points suffice; two identical exclusions fail. This repair can be publicly validated if the exceptions are publicly bound or a sound proof of their inequality is available. It is NOT a universal FE repair: actual bad sets need not be singletons or efficiently provable disjoint, and generic verification of emptiness may be computationally difficult. A second capsule cannot simply be asserted secure.

The appropriate future one-honest acceptance condition is a separately proved, **universal** implementation theorem:
  forall x,S,rho,w:
    ValidParams(x,rho) AND R_orig(x,w)
      => Eval(Build_R(x,S;rho),w)=S.
Then a sound ZK proof of correct construction, ValidParams, exact context/graph/capsule and native signature binding can transfer that theorem to arbitrary accepted malicious participant capsules *before irreversible funding*. If FE correctness is only with overwhelming probability over honest coins, that theorem does not follow. Public seed mixing with at least one fresh honest contribution can deter deliberate bad tapes in a bounded abort/session game, but it does not fix the pointwise-versus-universal error or prove erasure. Malicious participants can still abort before funding; they must not be allowed to leave funded coins dependent on bad/withheld capsules.

The concrete setup proof must bind common protocol/chain IDs, claim/outpoint, burn/amount/recipient/replay state, source baseline, Bitcoin anchors/window, actual ancestry/strict contextual AuxPoW, LC depth, deadline/reset, native sighash and safe transaction, all public keys, and session/capsule identifiers. It must verify graph/no-bypass and retrievable bytes before funding. One honest participant protects its bypass signing key; the other N-1 may retain theirs. A watcher with one valid ORIGINAL witness must locally open all N separate contributions without an online quorum. These are conditional obligations, not newly implemented setup security.

## Reproducible bounded check
A standard-library Python checker was executed twice, obtaining byte-identical JSON. In a toy 12-bit domain with 512 accepted witnesses it exhaustively verified: fixed-w failure 1/512 under uniformly sampled one-exception coins; every one of 512 capsules has some failing valid w; two distinct one-point exceptions allow every w to open at least one, duplicates do not; one catastrophic bad tape has honest probability 1/4096 but can be intentionally selected; XOR of a fixed malicious share and a uniform honest share is uniform. Checker SHA256 842e8534da35d9dceaa97159514f525bff48254ec73a060922fe5933962c2890. Both output hashes acb29366d3bd0893b5d85a6b2e6054c97dd76a5058b0991fe20b1386baf002e0. No FE, ZK, PoW, original witnesses, Bitcoin Script, QPT cryptographic tests or native signatures were involved.

## ORIGINAL missing advance
NONQUALIFYING. No practical serialized classical-PPT Build_orig(x_W,sigma_cancel)->C and public Open_orig(C,w)=same frozen safe cancellation for all qualifying ORIGINAL source witnesses has been constructed. No full-public FALSE/hard-TRUE QPT extraction to an actual original certificate, no native forgery/work reduction, and no complete malicious setup composition are established. The approved three independent OR grounds and claim-bound post-PQ AuxPoW authentication remain unchanged. Next work must construct *source-conditioned secret delivery*, not revise this setup quantifier or iterate an old hash-pad/graph attack. No user progress notification, PR comment, Core/production modification, deployment, transfer or automation change is warranted.