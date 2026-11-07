# Run 147 — one-bit laconic release is payload-complete for native-key escrow

Status: new conditional reduction; **not** a construction of QPT Ext-WE/PAoK and not a completed WKEM.

Verified current `syscoin/PVUGC#1` before this work: branch
`research/pq-wkem-validation-20260918`, head
`ee53ac6383f1327906f05550e2c709a9b7e93ff5`, open/draft/unmerged, latest substantive
ordinary PR comment `5852515576`.

Exact current-head inputs reread: Run123 blob
`2eefa25de7f5a9b9c65abf15a20bb4ae6564702e`, Run126
`94d1a6246da77f561ecacd84ce78917d6121dc33`, Run127
`ceb891a850663557169597c0ddf7068b67791ab3`, Run128
`a534790501f9996bf5af45708d8c16a6267f9569`, and keyless-native
`dffe6c85dc3bf63652ba7927d1593e2ee6549608`.

## Result 1 — arbitrary-message Ext-WE is unnecessary

Faonio–Nielsen–Venturi (FNV), *Predictable Arguments of Knowledge*, full version
2017-01-13, Definition 3 uses a one-bit Ext-WE message space. Theorem 3 proves in
the classical model that PAoK for `R` exists iff Ext-WE for `R` exists. Their
PAoK-to-WE ciphertext is `(c, beta xor b)` for `(c,b)<-Chall(x)`, and a witness
computes `Resp(x,w,c)=b`. Footnote 13 explicitly states arbitrary-length messages
can be handled by independently encrypting each bit.

Hence a one-bit QPT Ext-WE/laconic-PAoK primitive, if constructed, is sufficient
to escrow a polynomial-length future-native signing seed `S`.

Setup may sample `S`, derive `(sk,vk)`, publish one one-bit capsule
`gamma_i=EWE1.Enc(x,S_i)` per seed bit, and erase `S,sk` under the already-allowed
one-honest N-of-N setup. Every ORIGINAL valid witness reconstructs the same `S`,
then uses ordinary native signing. Bitcoin does not evaluate `R`.

## Result 2 — exact accepted-spend reduction

Let `S,R <- {0,1}^l` independently. Hybrid `H_j` encrypts
`R_1..R_j,S_(j+1)..S_l` while always publishing `vk=Pub(Derive(S))`. Let `p_j`
be an arbitrary QPT attacker's probability of producing an accepted signature on
the exact branch-bound transaction.

`p_0=rho` is the real attack probability. In `H_l`, all encrypted bits are
independent of the real native signing seed, so for a fresh branch-specific key
`p_l <= epsilon_SIG` under the exact QPT native-signature forgery game.

Pick `J` uniformly. The standard one-bit Ext-WE challenge encrypts uniform `beta`.

* If `S_J != R_J`, the challenge bit is exactly one neighboring-hybrid plaintext.
  On an accepted signature guess `beta=S_J`; otherwise guess `beta=R_J`.
* If `S_J == R_J`, the neighboring hybrids are identical. Ignore the challenge,
  simulate the common endpoint with public encryption, and guess uniformly.

Exactly,

`Pr[guess beta | J=j] = 1/2 + (p_(j-1)-p_j)/2`.

Averaging telescopes:

`Adv_EWE1 = (p_0-p_l)/(2l) >= (rho-epsilon_SIG)/(2l)`.

Thus for polynomial `l`, unauthorized accepted native spend gives either a
non-negligible one-bit Ext-WE/PAoK attack whose **QPT extractor** must return an
ORIGINAL source witness, or a QPT native-signature break. The wrapper is
straight-line: one attacker invocation, no rewind, no QROM programming, no
quantum-state cloning.

## Result 3 — correction to Run146's auxiliary-input concern

Run146 treated `vk=Pub(S)` as if it necessarily required a separately assumed
correlated-auxiliary-input Ext-WE theorem. That was too strong.

FNV Definition 3 has a two-stage adversary `A=(A0,A1)`: before the random-bit
challenge, `A0` uses its own randomness and any separately supplied `z` to output
`(x,st)`. Our reduction can itself sample `S,R,J`, derive `vk`, create every
non-challenge capsule, and generate all application manifest/branch/context data.
Those setup-generated correlations live in simulatable reduction state `st`.

What remains unresolved is genuinely external classical/quantum side information
that the reduction cannot reproduce. General arbitrary-aux Ext-WE has known
negative evidence (Garg–Gentry–Halevi–Wichs; Boyle–Pass), so the final QPT theorem
must state the exact external-auxiliary model. The wrapper itself uses one copy and
does not rewind/clone it.

## Security scope

FNV is classical PPT as published; its laconicization uses classical
Goldreich–Levin. Adcock–Cleve prove a quantum Goldreich–Levin theorem, but this
checkpoint does **not** claim a full port of FNV laconicization to arbitrary
stateful QPT provers/quantum auxiliary advice.

Therefore the remaining core primitive is now minimal:

`Chall(x)->(c,b)` and `Resp(x,w,c)=b` for every ORIGINAL valid witness,

with arbitrary-QPT successful prediction implying an ORIGINAL source witness or an
independently justified PQ-hardness break, and with Run126's Ext-side target
non-resampling requirement.

Run123 SDMSH is a stronger multi-bit dual-mode version that would mask a whole
native seed at once. No standard-LWE/SIS realization is established here.

## Reproducible check

`bitwise_laconic_extwe_native_escrow_run147_check.py` passed syntax validation and
two byte-identical runs with **501 assertions**. It checks
same-seed recovery, the neighboring-hybrid identity on a complete `l=2`
point-indicator basis (covering all 65,536 deterministic event tables by linearity),
64 seeded arbitrary event functions for `l=3..6`, exact recovery rows for
`l=1..8`, and context separation. It is algebra/probability validation only.

Next handoff: construct the **one-bit source-predictable QPT response itself** from
standard QPT-LWE/SIS or force that bit to a source-bearing Hair–Sahai low-rank
representation. Do not return to Bitcoin VM/proof verification or another native
wrapper.

The practical generic-NP PQ WKEM stopping condition remains **NOT MET**.
