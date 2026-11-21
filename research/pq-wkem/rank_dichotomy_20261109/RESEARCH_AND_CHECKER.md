# Public-affine hash/XOR release — polynomial-rank dichotomy

**Status:** exact scoped security-class exclusion, not a practical generic witness-KEM or a breakthrough. No user-facing progress comment warranted. Work is offline/hash-only; no lattice, DLog group, external research, or online release issuer.

## Continuity and new result
This follows PR #1's R168 complete-work/Pow versus public XOR clause-mask closure and the MDS same-witness experimental checkpoint. R168 already gives an explicit polynomial XOR attack on every FALSE or TRUE 3-CNF for its particular per-occurrence mask class. **New here** is the universal no-middle-regime rank theorem for *any* polynomial-dimensional publicly indexed affine release encoding—not another instance of that particular splice.

Let K and r_1,...,r_t be independently uniform k-bit blocks, and let the published N-block mask view be

    E = b K XOR C r,

with public b∈F_2^N, C∈F_2^{N×t}, and N,t polynomial in original input/security parameters. If b is outside the column span of C, a classical polynomial-time Gaussian elimination finds public v satisfying vᵀC=0 and vᵀb=1. Consequently vᵀE=K **without a witness**, even if the ORIGINAL satisfiable statement is hard-TRUE. If b=Cz lies in the column span, write E=C(r XOR zK), which is distributed independently of K. Therefore public linear-affine encodings have only two regimes: direct deterministic public K extraction or perfect K hiding in the E view. No computationally hard intermediate regime occurs in this explicitly public matrix model.

If *any* valid ORIGINAL witness opens the key by a linear combination of the published E rows, its choice vector necessarily satisfies vᵀC=0 and vᵀb=1. This proves b outside col(C), so public elimination **automatically** recovers K without that witness. The same argument extends to arbitrary finite fields and to polynomially materialized coefficient-space masking in Boolean quotient or clause-secret-sharing gadgets. A public hash checking key CK, a native signature masked under H(K), or a public AuxPoW commitment cannot undo that direct recovery.

This DOES NOT rule out computationally hidden/nonlinear incidence, succinct exponentially dimensional representations, quantum-hardened source-WE, or genuine source-specific cryptographic work relations. A nonlinear/hash construction must instantiate its public evaluator and full-public simulator, not merely assert that a hidden source oracle can supply r(w) or that post-hoc R(x,w) checking prevents raw ciphertext recovery.

## Executed exact rank checker
An actually executed Python-standard-library checker tested 1,015 deterministic random public matrices (2≤N≤8, 1≤t≤5). Of these, 778 admit direct public key recovery, checked for every possible mask; 237 give identical full public distributions for K=0 and K=1. Source SHA256 b51c08a5fe2ef2fda56fe603dc61330438557542cc23ad826caabc1b0cafc7a3. Captured output SHA256 0dce48fc45bcb999934a4a269a0276b36f75e6c32394b32b11b1f6f750ae273c. The bounded test only checks elementary finite algebra, not QPT security or original-source soundness.

A standalone minimal checker (Python 3.10+) for both branches of the theorem:
\`\`\`python
from functools import reduce
def enc(b,C,K,r):
    return (b if K else 0)^reduce(int.__xor__,(c for i,c in enumerate(C) if r>>i&1),0)
# b=C0 XOR C1 => the entire public distribution independent of K.
C=[0b101,0b011]; b=0b110
assert sorted(enc(b,C,0,r) for r in range(4))==sorted(enc(b,C,1,r) for r in range(4))
# b outside span(C): the public v=100 extracts K for every mask.
C=[0b001,0b010]; b=0b100; v=0b100
for K in (0,1):
    for r in range(4):
        assert ((enc(b,C,K,r)&v).bit_count()%2)==K
\`\`\`

## Constructive handoff
No polynomial ORIGINAL arbitrary-NP Build_hash/Open_hash meeting the same-capability and arbitrary-QPT recovery-to-ORIGINAL-witness conditions is constructed. Do not spend iterations optimizing degree, width, sampling, or storage of public affine masks. A viable next candidate needs *nonlinear hash-protected consistency* of complete authenticated Syscoin/AuxPoW evidence with SAME frozen native capability for every valid certificate, and no public direct key projection. Publicly known OutcomeID is not WorkID and neither unauthenticated semantic labels nor independently encrypted future WorkIDs solve release. Malicious N-of-N ceremony, joint auxiliary inputs, and honest-source observation remain open.
