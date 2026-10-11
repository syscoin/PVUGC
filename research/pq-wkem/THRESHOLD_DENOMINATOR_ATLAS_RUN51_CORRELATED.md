# Run 51 addendum — correlated public linear masks still collapse to an affine dichotomy

The first Run-51 theorem handles independent per-component ideal masks.  This addendum
closes the obvious next repair: use a single correlated public linear mask across all
threshold/atlas components.

Let any linear secret-sharing generator be written

```
s = b K + G rho,
```

with uniform share randomness `rho`.  Let `T` be the public linear map that embeds the
share vector into the complete coefficient/output space (this includes the public
denominator directions), and let `R` be uniform in an arbitrary public joint linear
mask subspace `V`.  The complete transcript is

```
C = T b K + T G rho + R.
```

Define

```
W = V + im(TG),    Delta = T b.
```

Then `C|K` is exactly uniform on `W + K Delta`.  Therefore:

* if `Delta in W`, all key-conditioned public distributions are identical and no
  decoder, even unbounded or witness-parameterized, obtains key information from this
  transcript;
* if `Delta notin W`, public Gaussian elimination finds `lambda(W)=0` and
  `lambda(Delta)=1`, hence `lambda(C)=K` exactly for every share/mask randomness.

The proof is finite-dimensional linear algebra: `(rho,R)` maps linearly and
surjectively onto `W`, so every element of `W` has the same number of preimages and the
sum is uniform.  Translation by `K Delta` either preserves `W` or moves to a disjoint
coset.  In the latter case a public separating functional exists.

This is an application of the affine-subspace algebra already isolated in Runs 41/46
to the Run-51 threshold-denominator composition, not a newly named hardness
assumption.  It means that replacing independent component masks by arbitrary **uniform
public joint linear correlations** does not create witness restriction.  The surviving
correlated-mask direction must be nonlinear/computational and needs a complete-output
reduction to an independently justified PQ assumption.

## Validation actually executed

A separate standard-library checker was executed twice with byte-identical JSON.  It
samples 400 random joint-mask fixtures over `F_5`, alternating additive `3-of-3` and
Shamir `2-of-3` sharing.  For every fixture it independently enumerates the complete
transcript distributions for keys 0 and 1 and checks that exact total variation is 0
iff `Delta in W` and 1 otherwise; on the exposed branch it also constructs and checks
the public separator.  The executed run enumerated 125,320 transcript samples with
multiplicity, with 378 public-separator fixtures and 22 identical-distribution
fixtures.  These finite checks validate the implementation only; the theorem above is
the proof.

This addendum does not rule out nonlinear/computational correlated masks, encrypted or
obfuscated source-witness-selective helpers, or the still-missing arbitrary-QPT
key-recovery-to-source-witness/PQ-break reduction.  The stopping condition remains
unmet.
