# Run 366 — Coherent-query period attack on a single acyclic local release frontier

New bounded, oracle-relative falsifier. Draft PR head at research start: ca62defc770b003b58bcef8a4296ce7e6f73799b. Exact live dependencies: Run 259 source-binding blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2 and Run 358 note blob 355829fcfc94d4a7904c78e1993756056a86e21d.

## Exact synthetic construction
Choose classical-PPT one-way f, sample z and publish y=f(z). Independently choose nonzero n-bit s, interpreted as one native signing seed K=s, and publish correlated native verification key PK(s). In an IDEAL-ORACLE model, make a single publicly callable F_s satisfy F_s(a)=F_s(b) iff a=b or a XOR b=s; sample independent injective output labels for the XOR cosets. The ORIGINAL relation checks f(z)=y, a!=b, F_s(a)=F_s(b), plus the true-statement flag and exact context. An honest witness (z,a,a XOR s) releases K=a XOR b. EVERY valid ORIGINAL witness obtains exactly the same K; intermediate witnesses remain different. Release stays off-chain; native signing is an abstract conditional endpoint.

IMPORTANT: The random exponential-size ideal oracle is not a standard-model classical-PPT public setup or a succinct public circuit. No concrete local mixer, PK signature, Bitcoin graph or full false-instance security has been constructed.

## Coherent QPT attack
Using the unitary |a,t> -> |a,t XOR F_s(a)>, prepare uniform input superposition, query once, Hadamard the input and measure r. For each XOR coset, the amplitude is 2^(-n)*(-1)^(r·a)*(1+(-1)^(r·s)). Distinct coset labels are orthogonal, hence Pr[r]=2^(1-n) when r·s=0 mod 2 and zero otherwise. After k independent measurements, Gaussian elimination returns the unique nonzero kernel vector s with failure <=(2^(n-1)-1)*2^(-k). k=n-1+lambda gives failure <2^(-lambda). This is genuinely quantum, polynomial-query recovery of the entire signing seed WITHOUT the independent source preimage z.

For classical black-box F-only algorithms, q queries reveal no period information before a repeated output except excluded XOR differences D among queried inputs. A correct collision/guess succeeds with probability <=min(1,(|D|+1)/(2^n-1)) <=min(1,(binom(q,2)+1)/(2^n-1)). This bound EXCLUDES pk(s), which might leak additional information. Quantum attack does not rely on pk. A publicly supplied polynomial-size classical evaluator can be reversibly evaluated in superposition by a QPT adversary; the ideal F_s has no proved such compact realization.

## Source binding and caveats
Conditionally assume f remains QPT one-way with the independent ideal quantum-oracle and native checking-key public view. A hypothetical extractor returning an ORIGINAL (z,a,b) from the Simon key-recovery adversary would invert f. This is an oracle-relative separation, NOT a standard-model QPT security theorem; false-instance full-view key hiding is separately UNPROVED. Run 259 establishes accepted-representation -> ORIGINAL or its stated SIS break, but cannot force this attack to submit a source representation. One frontier suffices: no cycle, gauge synchronization, multiple capsules or comparable public reversible paths. Random output-label permutations do not change the attack. Malicious setup, auxiliary correlations, native binding, cross-UTXO reuse and coherent implementation are not solved.

## Reproducibility and references
Exact executed standard-library checker simon_local_boundary_run366_compact_check.py, captured byte-identical output and provenance accompany this note (4426 finite assertions, Python syntax PASS). Full 1,101,703-assertion local checker/derivation is separately preserved. These checks validate Simon interference identities, NOT practical QPT security.

Literature: Daniel R. Simon, On the Power of Quantum Computation, SIAM J. Comput. 26(5), 1997, DOI 10.1137/S0097539796298637; Alagic-Russell, arXiv:1610.01187; Canetti-Chamon-Mucciolo-Ruckenstein, ePrint 2024/006. No audit of their complete proofs or refutation of full RIO is claimed.

Result: classical local-mixer hiding alone cannot justify QPT security under coherent evaluation. Classical practical setup, all-public-view false-instance QPT hiding, arbitrary-QPT early recovery -> ORIGINAL, N-of-N erasure/abort, multi-capsule composition, and concrete 128-bit resources are still UNPROVED. No production changes; practical WKEM UNSOLVED.
