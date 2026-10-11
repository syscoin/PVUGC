# Run 399: dense full-rank false-statement leakage survives public frame mixing

Actual draft PR starting head: `7b8f3d965528b90db12adaf302627b6a408ad8b6`. Exact upstream Run 398 note blob:
`016f999eb7b74859054ec69e86b87ae3b1cba977`.

**Scope:** focused falsification of a natural proposed repair to Run 398's
Regev-style LWE-decryption-witness release frontier. NOT a general attack on
LWE, witness encryption, source-aware RIO, or a complete PQ WKEM.

Let the ORIGINAL relation be `R_dec((A,b),(s,e))=1` iff
`b=As+e mod q`, with centered `||e||_infty<=B`.
Protect each bit `k` as `u=A^T r`, `v=b^T r+floor(q/2)*k` for
independent binary encryption coins `r`.

**Theorem.** Suppose a public full-column-rank `A` has
`A[2]=A[0]+A[1]` and a candidate `s_*` is publicly computable.
Choose `b=A*s_*+t*unit_row(2)`, with `3B<t<q-3B` and disjoint
modular sets `{0,t}` and `{mu,mu+t}`, where `mu=floor(q/2)`.
Let `h=unit_row(2)-unit_row(0)-unit_row(1)`. Then `h^T A=0`,
`h^T b=t`. A valid source witness would imply
`h^T e=t mod q` but `|h^T e|<=3B`: impossible. The statement is
false. Nevertheless `rank(A)=n`, and `h^T b!=0` gives
`rank([A|b])=n+1`.

For **every** encryption randomness choice,
`v-s_*^T u=t*r[2]+mu*k mod q`. A classical PPT adversary obtains
the entire signing seed by distinguishing the two disjoint supports,
without possessing an ORIGINAL witness. Public checking keys, additional
capsules or a quantum computer are unnecessary.

**Dense public-frame family.** Begin with the relation among rows
`(1,1,0,...)`, `(1,0,1,...)`, `(2,1,1,...)`; add enough rows for
column rank and distinct filler rows `(1,20+i,2,...)`. Select the
public near-secret `s_old=(1,2,3,23,24,...)`, and set
`b=A0*s_old+t*unit_row(2)`. Scramble all columns by the *public*
invertible `T=I+J`, with determinant `n+1` modulo `q`.
Set `A=A0*T` and `s_*=T^{-1}s_old`. The short row relation and
ciphertext cancellation survive. In the checked instances every A
entry is nonzero, all rows are distinct, all b entries are nonzero
and pairwise distinct, and both A and [A|b] have full rank.
A public set of n unmodified independent rows recovers s_* by
Gaussian elimination; it is a near-key, NOT an ORIGINAL witness.

**Exact finite checks.** The attached standalone JavaScript checker
was executed as published and its JSON output captured. It checks
(31,3,6,1,10), including all 31^3 candidate witness secrets, and
(12289,3,512,1,10), (12289,8,512,1,10), including full 256-bit seed
recovery. All satisfy `mB<q/4`, the restricted honest all-witness
rounding margin. The independent extended Python checker, output and
full derivation are preserved locally. Neither checker establishes
cryptographic hardness or actual SLH-DSA native signing.

**Important distributional distinction.** Run 398's leftover-hash
bound applies to a *uniformly sampled* public key. A chosen-false
statement with this full-rank, dense key is not uniformly sampled:
that bound cannot protect it. Regev's standard PKE theorem is about
the stipulated honestly generated key distribution, not an all-false
witness-encryption security game.

**Attack taxonomy:** (1) affine seam `v-s_*^T u` leaks the seed;
(2) public invertible gauge T does not close it; (3) checking only
rank/nonzero/distinct entries misses the seam; (4) one capsule suffices;
(5) only public chosen-instance data are used; (6) chosen-instance
coins need not be retained because s_* is publicly solvable; (7)
branch/UTXO separation remains absent; (8) the real vk is correlated
with recovered seed and does not rescue hiding; (9) attack classical
and therefore also QPT, not a new coherent quantum attack.

**Run 259 interface:** no accepted complete source representation
exists for this false statement; downstream supplied-representation
extraction therefore cannot save the release. Any surviving compiler
needs complete-public-output false-instance QPT hiding and true-instance
authorization-to-ORIGINAL extraction under independently justified
assumptions. This attack is not a proof against a genuinely
source-bound local-mixing circuit. No generic NP compiler, actual
N-of-N ceremony, Bitcoin endpoint, or concrete 128-bit security exists.

Primary background: Regev, STOC 2005,
https://doi.org/10.1145/1060590.1060603.
