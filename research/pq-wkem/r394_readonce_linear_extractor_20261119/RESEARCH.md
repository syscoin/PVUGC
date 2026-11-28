# R394 — Read-once public linear-state source release: constructive witness extraction (NONQUALIFYING)

## Scope and precise new route
At actual PVUGC PR #1 head `4e2719cc77ae5bf9f65ac3bcc235c2665aa89a90` on `research/pq-wkem-validation-20260918`, read R393 note blob `539521dcc0b4b2fcbea9566142bbd14cb8956432` and R392. PR comments since 2026-11-18T00:00Z returned `[]`. No new Core #609 source assertion/test, actual SHA/AuxPoW certificate, Bitcoin signature, or QPT test.

R393's equality rank bound assumes the x-input half precedes y. An alternative candidate avoids that cut by using a public **interleaved read-once** linear-state program, with private invertible gauge randomization. It can compute a Boolean predicate exactly and output a single frozen scalar key K on each valid input. Rather than another tensor sampling experiment, this pass constructs the class and proves a general **explicit public source-witness extractor** from its complete representation. The result is a family exclusion, NOT the missing FE/KEM.

## Candidate public serialization
For a fixed-length canonical ORIGINAL witness bitstream w=(w_1,...,w_n), let the builder publish initial row a, matrices M_(j,0),M_(j,1) in F_q^(d x d) for every input position j, terminal column b and D=S+K mod q. The prescribed public computation is

    E_C(w)=a M_(1,w1) M_(2,w2) ... M_(n,wn) b.

Exact source release would require E_C(w)=K != 0 on **every** R_orig(x_W,w)=1 and E_C(w)=0 on **every** invalid w. For any accepted w, S=D-K. Noncommuting matrices, arbitrary processing order, independently randomized public gauge transformations and nonzero Merkle-branch depth are permitted; the only structural restriction is **one public matrix choice per witness input bit**, with no hidden memory or private evaluator. d,n,log(q) must be polynomial.

## Exact constructive public extractor (lemma for THIS representation)
Maintain V_0=span{a}. After reading position j, define

    V_j=span({v M_(j,0),v M_(j,1): v runs over a basis of V_(j-1)}).

Store each independent row with ONE actual bit-prefix producing that row. Initially row a carries the empty prefix. Extend each saved row by bit 0 or 1; use Gaussian elimination to retain a basis of at most d rows, with their generating prefixes. Induction shows these rows span all actual prefix products a*M_(1,w1)*...*M_(j,wj). At the last step, test each saved row v against b. If there exists any valid witness w*, then E_C(w*)=K !=0, so the linear functional L(v)=vb is nonzero on V_n and must be nonzero on some saved basis row. Its stored complete prefix is an **actual** satisfying witness because the encoded function is zero on all invalid inputs. The value vb is K and S=D-K.

This algorithm runs in polynomial n,d,log q (naive O(n d^4) field operations) and requires neither the plaintext key nor the private gauge, a volunteered representation, nor a previously mined source witness. It extracts a **single globally consistent bitstream**; unlike R366/R289 it does not splice inconsistent local assignments. Consequently an explicit polynomial-width read-once linear-state compiler **faithfully** encoding a hard-TRUE ORIGINAL source relation would make obtaining a valid ORIGINAL certificate polynomial time. This is not a hash-only FE impossibility theorem: nonlinear public encodings, repeated input occurrences with cryptographically enforced global consistency, opaque matrices, and different source languages lie outside the lemma. If a source certificate is already easy/public, the conclusion is unsurprising.

## Executed constructed fixture and limits
A bounded standard-library checker built a dimension-4 public program for the NONLINEAR toy relation XOR over consecutive pairwise ANDs. Internally the accumulator stores a pending bit and running parity. The builder privately chose invertible gauges G_0,...,G_n and published M'_(j,b)=G_(j-1)^(-1)M_(j,b)G_j, a'=e_start*G_0, and b'=G_n^(-1)*K*e_accept, with D=S+K. Public evaluation telescopes to K on all valid assignments and 0 otherwise, giving every-witness common-key correctness. The extractor then recovered a valid witness, K, and S from **only** the published matrices/terminal vectors.

Executed checker twice, both completed and produced byte-identical output. Exhaustively checked all 64,256,1024 inputs for n=6,8,10 respectively. Counts (valid,invalid) were (28,36), (120,136), (496,528). The public extractor returned `000011`, `00000011`, `0000000011`; each recovered K and S. Maximum observed basis size was four. No source PoW, source authenticity, native Bitcoin signing, FE, malicious setup or QPT security was tested. Local checker SHA256: `00272644995928d42e08ec674b60ca4f2ea7e0fb84f2d557f9f39c98e6db8016`; both local outputs SHA256: `34d005f167d62403aedc96a2870e85e47e66394f94adaad9b4f8b8271be00d08`. The executed full checker/output files remain local-only, not represented as GitHub-published bytes.

## Security simulation and decision
For the TRUE capsule no hard-TRUE joint-public simulator or security reduction exists: the explicit public attack obtains an actual accepting witness and the secret. A synthetic FALSE capsule with terminal b=0 and independent uniform K appearing only in D=S+K would have exact transcript hiding, but would require the builder to recognize FALSE, and says nothing about the ORIGINAL source relation. **No joint-public FALSE ORIGINAL simulator was constructed.**

Do not further vary public read-once matrix dimension, gauge group, bit order or field. Read-many polynomial-width verification is expressively possible, but public independent choices at repeated occurrences reintroduce inconsistent local-path attacks unless a truly global **cryptographic** state is enforced *inside* release. A Merkle root or source-verifier if-check does not generate hidden source-conditioned labels. The exact unfilled operation remains a serialized classical-PPT `Build_orig(x_W,sigma_cancel;rho)=C`, public `Open_orig(C,w)=sigma_cancel` for EVERY original qualifying w, and a full-public FALSE/hard-TRUE QPT recovery/native-forgery reduction to ACTUAL relevant authenticated certificates or independently justified breaks, with one-honest malicious N-of-N setup, sibling capsules, source coin retention and native claim/outpoint binding. No change to the three independent ORIGINAL OR grounds, modern contextual AuxPoW rules, R316 correction, tag validity, LC-depth or deadline policy.

NONQUALIFYING. No PR comments, breakthrough notice, Core/production edits, deployment or automation change.
