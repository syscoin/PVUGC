# MDS same-witness masks — intermediate checkpoint (NOT a WKEM)
**Status:** exact source-consistency correlation gadget, not a polynomial public hash-only compiler, PQ security theorem or practical witness-KEM. No user-facing breakthrough, internet research, lattice/group primitives or production changes.

## Continuity
syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, initial pass head 3151fd04792e818292ade52a2c37439d4f392775. Read the exact hash_sealed_states_20261109/RESEARCH.md, SHA fd6576b982733e9ff7065f34b2a6cfe20f2e4820. A concurrent authorized R168 research commit advanced branch to 36b41e111b3352b3436ffb8909c4708cccfc7fa9; this checkpoint is based on that current head and touches only its own research directory. R168 tried polynomial source attestations requiring prohibited online signers; this experiment does NOT use them.

## Named candidate: witness-indexed simplex mask AND
Split the ORIGINAL relation into m clauses P_j(x,w), all on the **same full w** including all genuine required Syscoin/AuxPoW source checks. Let A_j={w:P_j(x,w)=1}. Over F_q for q>m, choose shares a_j with Σa_j=K, and for each complete witness w choose independent uniform r_w in F_q^(m-1). Set row vectors q_1=e_1,...,q_(m-1)=e_(m-1),q_m=-(e_1+...+e_(m-1)), and ideal locally accepted response Y(j,w)=a_j+<q_j,r_w>.

For EVERY w in ∩A_j, Σ_jY(j,w)=K exactly. If x is FALSE, for each full w the subset of exposed simplex rows is proper and linearly independent, so its responses are jointly uniform independent of a_j and K. Since r_w are independent across w, the ENTIRE false-instance ideal-table distribution is independent of K, against unbounded classical or quantum readers. This is an exact information-theoretic lemma for the ideal table, not a deployed/publicly constructible source oracle.

Single scalar masking with m=3 is unsound even if ∩A_j is empty: let u satisfy child checks {1,2}, v satisfy {1,3}. With scalar q=(1,1,-2), an unauthorized party combines -Y(1,u)+Y(2,u)+2Y(1,v)+Y(3,v)=K. Using m-1 simplex coordinates prevents all such cross-witness linear cancellations because each non-full per-witness row subset is full rank.

## Executed finite mathematics
Python-standard-library checker ran all proper row subsets for m=2..7, 100 synthetic TRUE/FALSE games per m, 1,000 exact scalar-splice counterexamples; 6,839 assertions passed. Actual local source SHA256 c96684a82ce9459792466bc88077fabcd5b39424b88abd94181dd975f0ad98d8, stdout SHA256 f89cd89d8142e5b56f62963be4f0f9d8a37271695eb03213d8a6bddc7519f190. These scripts and stdout are preserved LOCALLY, not claimed published on GitHub by this intermediate note.

## Explicit missing public compiler
The table needs an independently secret r_w for EVERY full w: exponential. Replacing r_w by public SHA(ctx,w) exposes each a_j from any easily found locally satisfying w; summing shares gives K even for FALSE original instances. Putting r_seed,a_j in public code exposes them. A hidden oracle or constrained evaluator that computes Y only on source-valid witnesses is NOT instantiated. The full-public malicious ceremony/QPT recovery proof remains open. Next: formal oracle-query extraction to an ACTUAL complete witness (with coherent queries), then directly test a concrete public hash instantiation rather than assume a secret evaluator. No standalone optimization.
