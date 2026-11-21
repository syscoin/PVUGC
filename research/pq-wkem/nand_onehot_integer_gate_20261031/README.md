# NOGC offline SOURCE experiment — no secure WKEM advance

**2026-10-31** · Original PR: syscoin/PVUGC#1 · Starting head: `12fd5365b54709ecfa0e35a143c5177615de1cf2` · Predecessor comment: `6549617219` · No external literature or web research.

This checkpoint directly continues CORN's nonbinary public-opening failure. A classical-PPT, witness-free **NAND-circuit-to-normalized integer SOURCE** repairs a real representation-level weakness: for `V` wires and `G` NAND gates, it constructs affine `Az=t (mod q)` with one-hot wire and gate blocks and threshold `L=V+G`, and **every integer affine opener `z` with `||z||₁≤L` extracts an actual ORIGINAL accepting circuit input** (for `q>L+2`). Every valid ORIGINAL witness has a deterministic one-hot lift of norm exactly `L`. The proof and all equations are in `RESEARCH.md` inside the bundled archive.

**It does not repair public release.** For any *rejecting* ORIGINAL input, evaluate the real trace then flip only the final NAND output to 1 and change its local selector from `(0,0,0,1)` to `(-1,1,1,0)`. This is a **public affine solution** `Az_bad=t` with `||z_bad||₁=||z_bad||₂²=L+2`, even on FALSE statements with no ORIGINAL witness. In the actual source-dependent q-ary LWE residual release

`β=Aᵀs+e,  τ=tᵀs+e*+g·m (mod q)`,

the fake obtains `g·m+e*−z_badᵀe`. If the bounded, centered, independent errors have magnitude at most `B` and honest deterministic correctness requires `g/2>B(1+L)`, then for **T protected symbol ciphertexts**

`Pr[any fake decoding failure] ≤ 2T exp(−(L+1)²/(2(L+3)))`.

At illustrative `L=2000,T=192`, this upper bound is `2^-1433.390171` — an **attack-success bound**, NOT a security estimate. No nonlinear release gate or structured-SOURCE QPT simulator was established; the earlier ordinary-QPT-LWE theorem on uniform random matrices does not apply to this chosen structured circuit compiler. The result rules out treating strengthened short-INTEGER representation soundness as arbitrary final-key recovery soundness. Native checking keys, preauthorization signatures, unrelated capsules and selective opening do not prevent direct key extraction.

The exact standalone Python 3 checker, captured output, full proof, precise assumptions and provenance are in the accompanying `EVIDENCE.tar.gz` archive (no network, no dependencies). `python checker.py` passed **1070 checks, twice with byte-identical JSON output**: 37 NAND circuits, 97 satisfying ORIGINAL inputs, exhaustive short-integer soundness on one NAND gate, correct recovery of the SAME precommitted mock key by three distinct ORIGINAL witnesses across two related three-XOR-lane capsules, two unauthorized full-capability recoveries on FALSE, and **6000/6000** unsafe individual decryptions even at a deliberately narrow noise margin. The checks are toy finite arithmetic, not a QPT test or a native PQ Bitcoin implementation.

**Next indispensable equation:** actually build classical-PPT `Comp(R,x,context,vk)` and public `Lift` enforcing ORIGINAL consistency cryptographically, with every valid ORIGINAL witness recovering the identical bound capability, and a complete joint-public QPT reduction from arbitrary unauthorized final-key recovery/native fresh forgery to an ORIGINAL witness or an independent PQ break. Neither an optional public precheck nor another semantic L1 gap suffices. No production, main, workflow or other repository files are changed.

Archive SHA-256: `0093bb991e53464105d12c6dc8a280d48e5a3a089a1412335f9750b802984deb`.
Full derivation SHA-256: `1c2095b3e5a57047eb7819ec9baf361273f7aa9fd43dd17d45ea312ad97893e0`.
Exact checker SHA-256: `4cb7910eb9386c9b7309dbb5ac84638c3a3ed55ee7c4198be6c48acb76e94f37`.
Captured output SHA-256: `7c5a736afee3ed43ed9b3f710cc96fcc98f25f7e3b4121c12d3d700b20edaa59`.
