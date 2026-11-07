# Run 56 — noisy affine branching transport: common-path correctness and complete-output frame recovery

**Status:** constructive common-representation attempt plus an exact/stable complete-public-output attack on its natural well-conditioned regime. This is **not** a completed witness KEM and does not establish a generic impossibility theorem for all noisy program encodings.

Starting verified PR head: `d8effe94f5bc54f6509baffdd89e7f3bf3e3bd66` (Run 55). The latest Run-55 result and the existing branching-intertwiner, normalized-short-kernel, SIS-lift, and Gap-OHLC records were read before this pass. No external literature or web search was used. Production code is unchanged.

## 1. Why this attempt is different

Runs 53--55 isolated a concrete missing property: different public pseudorepresentations must not be able to answer different local tests and then recombine the resulting pieces. Run 54's hidden edge pads achieved the desired cancellation in an ideal plaintext algebra, but the natural linear public realization telescoped for the attacker as well. Run 55 then showed that merely hiding a sparse local selector still leaves a polynomial covering list of exact false representations.

This pass tries a genuinely different binding mechanism. Instead of releasing separately testable local shares, it encodes a witness as a **single path through a noncommutative layered program** and uses hidden setup frames that telescope only along one complete path. Unlike the exact layer conjugation rejected in `BRANCHING_INTERTWINER_AND_WE_BOUNDARY.md`, the frame equations are deliberately made noisy, with the hope that reconstructing the erased frames becomes an LWE-like noisy linear problem while a valid path still accumulates only correctable noise.

The complete-output audit below rejects the natural well-conditioned form of that idea before any new hardness assumption is introduced.

## 2. Candidate: noisy affine layer transport

Work over a field `F_q`. Let a public targeted layered program contain matrices

\[
A_{i,b}\in F_q^{d\times d},\qquad i=0,\ldots,L-1,\quad b\in\{0,1\},
\]

and public target `T`. A source witness `w` is accepted only if

\[
A(w)=A_{0,w_0}A_{1,w_1}\cdots A_{L-1,w_{L-1}}=T. \tag{1}
\]

Setup samples hidden layer frames

\[
R_0,\ldots,R_{L-1}\in F_q^{d\times d},
\]

chooses a key carrier `S_K`, and programs the final frame as

\[
R_L=R_0T+S_K. \tag{2}
\]

For small error matrices `E_{i,b}`, publish

\[
\boxed{C_{i,b}=R_{i+1}-R_iA_{i,b}+E_{i,b}.} \tag{3}
\]

Then erase the frames.

This setup knows the statement/program and the key carrier but not a source witness. After setup, every object required for decapsulation is public and no participant is online.

## 3. Proved positive identity: one common valid path telescopes to the key

For a candidate path `w`, define the public suffix products

\[
U_i(w)=A_{i+1,w_{i+1}}\cdots A_{L-1,w_{L-1}},
\]

with `U_{L-1}=I`, and let

\[
F(w)=\sum_{i=0}^{L-1} C_{i,w_i}U_i(w). \tag{4}
\]

Substituting (3) gives the exact telescoping identity

\[
F(w)
 = R_L-R_0A(w)
   +\sum_i E_{i,w_i}U_i(w). \tag{5}
\]

Therefore every valid source witness satisfying (1) obtains

\[
\boxed{F(w)=S_K+N_w,\qquad
N_w=\sum_i E_{i,w_i}U_i(w).} \tag{6}
\]

Thus the attempt has a genuine common-path property: all valid witnesses target exactly the same carrier, and the only witness-dependent term is accumulated noise. This is stronger than the componentwise interfaces broken by simple switching in Runs 53--55.

The finite checker validates (5)--(6) on 600 random `3 x 3` matrix programs over `F_101`.

## 4. Complete-output branch differences remove the next-layer frame

The full public transcript includes both branches at every layer. Hence anyone can form

\[
D_i=C_{i,0}-C_{i,1}.
\]

Writing

\[
\Delta_i=A_{i,0}-A_{i,1},\qquad
F_i=E_{i,0}-E_{i,1},
\]

one gets the exact identity

\[
\boxed{D_i=-R_i\Delta_i+F_i.} \tag{7}
\]

The crucial point is that `R_{i+1}` cancels **without a path and without a witness**.

### 4.1 Noiseless full-rank theorem

If `E_{i,b}=0` and `Delta_i` is invertible, then

\[
\boxed{R_i=-D_i\Delta_i^{-1}} \tag{8}
\]

is public. In particular, if `Delta_0` and `Delta_{L-1}` are invertible, the attacker needs only the first and last layer:

\[
\widehat R_0=-D_0\Delta_0^{-1},\tag{9}
\]

\[
\widehat R_{L-1}=-D_{L-1}\Delta_{L-1}^{-1},\tag{10}
\]

\[
\widehat R_L=C_{L-1,0}+\widehat R_{L-1}A_{L-1,0},\tag{11}
\]

and therefore

\[
\boxed{\widehat S=\widehat R_L-\widehat R_0T=S_K.} \tag{12}
\]

No accepting path is found or used. The source statement is relevant only to the intended correctness proof, not to the recovery algorithm.

The checker generated 500 random `GL_3(F_101)` programs whose branch differences were invertible at every layer. Equation (12) recovered the programmed carrier in all 500 fixtures.

### 4.2 Why calling (7) "LWE-like" is not a proof

Transposing one row/column of (7) can superficially resemble a noisy linear sample. But the coefficient is the **specific square branch-difference matrix** `Delta_i`, and the complete transcript gives the entire matrix product at once. When `Delta_i^{-1}` maps the error distribution back to a decodable small region, (8) is a direct public frame estimator, not an LWE problem.

Conversely, choosing `Delta_i` so that modular inversion spreads a small error almost uniformly may block this particular estimator, but that is not by itself an LWE reduction and can conflict with correctness because the same transition matrices also multiply path noise in (6). This run does not assert a general tradeoff theorem for every possible transition/noise family; it records the exact attack where the inverse is well conditioned for the actual error lattice.

## 5. Stable noisy attack on a norm-preserving signed-permutation instance

A concrete candidate demonstrates that noise does not automatically repair (7).

Take odd prime

\[
q=65537,
\]

width `d=2`, and at every layer

\[
A_{i,0}=I,\qquad A_{i,1}=-I. \tag{13}
\]

These are signed permutation matrices, so all suffix products are again `+/- I` and do not amplify entrywise error. A path is accepting for target `T=I` exactly when it contains an even number of `1` branches. Thus there are many valid witnesses, and every one must recover the same carrier.

Encode a bit as

\[
S_K=K\Delta_K I,
\qquad \Delta_K=8192. \tag{14}
\]

Sample each public-error entry from

\[
\{-2,0,2\}. \tag{15}
\]

The factor two is not a security assumption; it is merely a clean finite fixture in which the exact inverse of the branch difference preserves centered smallness. Over an odd modulus, scaling an error distribution by a nonzero public constant is an invertible relabeling.

Here

\[
\Delta_i=A_{i,0}-A_{i,1}=2I,\tag{16}
\]

and

\[
D_i=-2R_i+(E_{i,0}-E_{i,1}).\tag{17}
\]

So the public estimator

\[
\widehat R_i=-\tfrac12D_i\tag{18}
\]

has entrywise error at most `2` in the centered representation.

Using only the first and last layer as in (9)--(12), the resulting carrier estimate obeys the deterministic entrywise bound

\[
\boxed{\|\widehat S-S_K\|_\infty\le 6.} \tag{19}
\]

By contrast, a valid witness path of length `L` has, from (6) and the signed-permutation suffixes,

\[
\boxed{\|N_w\|_\infty\le 2L.} \tag{20}
\]

Thus in this candidate the witness-free complete-output attack is actually **less noisy** than the intended valid-witness evaluation. Any phase spacing chosen large enough to make all honest paths decode also makes the public estimator decode.

For the executed `L=12` fixture, `2L=24` and the key centers are 8192 apart.

## 6. Fresh validation actually executed

`noisy_affine_transport_run56_check.py` is standard-library-only and deterministic. It was executed twice after finalization; the captured JSON outputs were byte-identical.

It checked:

* 600 random `3 x 3`, length-5 exact telescoping identities over `F_101`;
* 500 random `GL_3(F_101)`, length-4 noiseless full-rank branch-difference attacks; 523 random program samples were needed to obtain 500 fixtures with all required invertible differences;
* 180 independent noisy signed-permutation setups over `q=65537`, `d=2`, `L=12`;
* **all 2048 even-parity valid witnesses per setup**, for **368,640/368,640** same-key decodes;
* **180/180** witness-free public carrier/key recoveries from branch differences;
* maximum observed honest first-entry noise `22`, below the proved bound `24`;
* maximum observed attack first-entry error `4`, below the proved bound `6`.

The checker SHA-256 is

`8ea0b4ccbeb4b1daa3bd45ba2d99f2ab81eebe44a039e5356e66e0d1d4f7155a`.

The captured validation SHA-256 is

`4051201f172ec563cd0767cb9c08515bc14f324cf856454ee4c18c7597417ac3`.

These tests validate the finite identities and the implemented attack. They do **not** establish LWE hardness, a generic-NP branching compiler, or security of an unbroken noisy transition family.

## 7. What is proved, what is rejected, and what remains open

### Proved

1. The noisy affine transport construction (3) has exact same-carrier telescoping along every valid common path, equation (6).
2. The complete public two-branch transcript always exposes the noisy frame equations (7).
3. In the noiseless full-rank case, invertible endpoint branch differences recover the programmed carrier exactly without a witness, equation (12).
4. In the explicit signed-permutation candidate (13)--(15), the public carrier estimator has deterministic error at most `6`, while every valid length-12 path has deterministic error at most `24`; hence the public attack decodes whenever the demonstrated honest decoder does.

### Implemented and tested

The algorithms and counts in Section 6 were actually executed twice with byte-identical captured output.

### Conjectural / not claimed

* No claim is made that every noisy affine program is insecure by this estimator.
* No claim is made that every generic-NP branching program can be transformed so that all branch differences are invertible or well conditioned.
* No claim is made that making the differences ill conditioned yields LWE security. That would require a real distributional reduction and a full correctness analysis, neither of which is supplied here.
* No claim is made that tests imply cryptographic security.

### Remaining central obligation

The run sharpens the next target. A surviving common-representation layer cannot merely add noise to an otherwise publicly solvable layer randomization. It must simultaneously ensure:

1. valid source paths evaluate with useful noise;
2. the **complete set of alternate branch encodings** does not expose low-noise frame/endpoint information through differences or invariant projections;
3. any residual computational hiding is reduced to a standard PQ assumption on the actual public coefficient distribution; and
4. arbitrary QPT early final-key recovery yields a source witness or such a PQ break.

The Run-42 SIS wrapper remains useful only after a release mechanism forces recovery of a sufficiently short normalized representation. Gap-OHLC remains useful only as a semantic/projective-gap interface. Neither result supplies the missing complete-output common-representation release.

The stopping condition is not met. The PR must remain draft/unmerged, and production code remains unchanged.
