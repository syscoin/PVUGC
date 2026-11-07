# R37: PRE-SIGNED CAPABILITY / QPT strong-forgery split (2026-11-03)

## Provenance and exactly one component

Offline continuation of syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918 from verified SHA d0850bfd89356bc6935288a9f3d02bc2eff6074a (open/draft/unmerged; comment 6601870772). Read exact R36 RESEARCH.md blob 97d6211be34d905fe5a10952459b425f74c1f911 and R35 RESEARCH.md blob 986ff360ea2853308127ace2b99a5476e4645a92; no PR-wide diff or outside research.

**New constructive subcomponent:** Replace the encrypted signing SECRET in R35/R36 by a single fixed, already preauthorized SIGNATURE sigma_* on one immutable native challenge sighash m_*. Valid ORIGINAL witnesses still obtain EXACT SAME capability bytes sigma_* by public off-chain capsule opening. For a distinct accepted canonical signature on that same message, a straight-line arbitrary-QPT adversary-to-QPT-strong-unforgeability reduction exists even when the complete public SOURCE is correlated with sigma_*. This removes a separate native alternative-signature proof obstruction; it DOES NOT prove unauthorized prescribed-sigma recovery -> ORIGINAL witness and is NOT a general PQ witness-KEM.

## Classical Build/Open and public view

Let x bind R_x's ORIGINAL verifier/relation identity, claim/UTXO, branch, actual source burn/authorization/output, SYS/BTC header/AuxPoW/tags/ancestor/window data, and *exact* native verification key vk_*, fixed challenge transaction digest m_*, sighash semantics and spending path. The fixed message and all pre-signature/data availability must be settled before irreversible funding; no signing an unknown later message or relaxing sighash by assumption.

For each claim/path keypair (sk_*,vk_*) generated with the intended one-honest N-of-N preauthorization, sign m_* ONCE before funding to obtain canonical sigma_*; protect/erase the spending signing secret, never encrypt sk_* or retain bypass paths. Let K=bytes(sigma_*). For each source branch and scope with independent coins rho_i publish C_i <- R35/R36.Build(R_x,K;rho_i), with x,vk_*,m_*,public context, checking key CK and publicly derived auxiliary/related capsules. All source CK/aux in the native-forgery reduction must be efficiently samplable from (vk_*,m_*,sigma_*,rho_i,public context) without sk_*; external quantum advice independent of sk_* conditional on these inputs is permitted. Secret-sk-correlated auxiliary inputs are excluded; this is NOT a proof for malicious N-of-N setup. Every ORIGINAL valid w induces its own Boolean assignment z_w with all clause failures zero, so every capsule satisfies C_i(z_w)=Delta*bits(sigma_*)+e(z_w), and on the existing simultaneous decoding-good event outputs identical sigma_* for all distinct w, including adaptive witness choices.

The opener checks R_x(w)=1 OFF CHAIN at the ORIGINAL relation, decodes sigma_*, checks native Verify(vk_*,m_*,sigma_*) and only submits the ordinary fixed-message native signature on the intended challenge path. Bitcoin must not execute NP/VM/PCP/BitVM traces. Native SLH-like signatures and a no-EC P2MR-like output remain CONDITIONAL, not deployed or assumed available. The original R35 polynomial-size source is still impractical for realistic generic NP, and fixed-message preauthorization may be impossible for challenge transactions whose sighash depends on unpredictable future data.

## Exact full-public QPT theorem

The real game draws (sk_*,vk_*) <- KeyGen(1^lambda), sigma_* <- Sign(sk_*,m_*), and independent public source coins rho_i. Give arbitrary QPT A the *entire* samplable joint public transcript (relation/statement, vk_*, m_*, source capsules, CK, context, relevant auxiliary, related capsules and adaptively requested non-target openings), with quantum auxiliary advice whose sampling can be reproduced from the same available inputs. An adversarial output sigma_A is accepted on this one path only if canonical and Verify(vk_*,m_*,sigma_A)=1. Its events partition EXACTLY:

Pr[accept] = Pr[accept and sigma_A=sigma_*] + Pr[accept and sigma_A != sigma_*].

Construct QPT B in a strong-unforgeability-under-chosen-message-attack game: obtain vk_* from challenger, query Sign(m_*) once, receive sigma_*, run the FULL actual Build and joint CK/aux sampler using the known sigma_* and fresh independent coins, run QPT A once, and return (m_*,sigma_A) when accepted and byte-distinct. This is a perfect straight-line simulation and obtains a strong forgery (message already signed). No SOURCE-opening oracle, adversary-supplied representation, extraction of signing sk, random-oracle model, generic group or classical rewinding is used. Therefore

Pr[accept and sigma_A != sigma_*] <= Adv_QPT-SUF-CMA(Sig,B),

assuming this exact signature implementation is QPT SUF-CMA secure in the applicable classical-query signing-oracle model. Ordinary EUF-CMA security does not suffice. When A outputs sigma_*, this theorem says NOTHING about whether an ORIGINAL witness exists or can be extracted; that is exactly the missing hard-TRUE SOURCE theorem.

The full view may contain publicly derived CK from sigma_* because B knows sigma_* via its signature oracle. It may NOT contain other uncomputable sk-dependent values. This simulator is for NATIVE STRONG FORGERY, not the arbitrary-FALSE zero-capsule simulator: a FALSE simulator without sigma_* may still fail to reproduce signature-dependent checking-key correlations. Related capsules and other scope exposures are covered only when B can generate them from sigma_* and recorded coins; any released target capability immediately permits replay. Use a separate key per fully fixed path, or prove multi-query SUF for one key across several signed messages. Different signature encodings, alternate graph edges, or a changed m_* are outside this theorem.

## Independently instantiated QPT hash-based fixed-message signature component

For a fixed L-bit message m_*, choose independent uniform s_{i,0},s_{i,1} in {0,1}^lambda, publish vk_{i,b}=H(s_{i,b}), and pre-sign sigma_*=(s_{i,m_i}) for i=1..L. Native verification of THIS Lamport scheme is not available or assumed on Bitcoin. Any canonical accepted sigma_A != sigma_* on m_* changes at least one revealed preimage, giving s' != s with H(s')=H(s). Assume independently that random-input quantum second preimages are QPT-hard, i.e. from (X,H(X)) with X uniform no QPT finds X' != X with equal H with nonnegligible probability. B embeds the given X into a uniformly chosen revealed index J among L indices, otherwise samples the entire honest public view and runs A ONCE. On any distinct accepted sig at least one index differs; with probability >=1/L that index is J. Thus

Pr[accepted distinct same-message signature] <= L * Adv_QPT-second-preimage(H).

This is a straight-line QPT black-box proof using an independent hash assumption, not a renamed WE/iO/WPRF assumption. It only covers the FIXED signed message; other-message Lamport forgery needs quantum one-wayness for unrevealed labels. Concrete security for SHA-256 and an actual native SLH-like endpoint is NOT established by this toy. With 16-byte secrets and a 256-bit fixed digest, Lamport alone gives 4,096 signature bytes and 16,384 public-key bytes BEFORE SOURCE capsules, with NO 128-bit-security estimate.

## Executed checker and limits

CHECKER.js below is its EXACT executed V8 source, with a deterministic, deliberately insecure 17-element toy hash (square mod 17). It checks every ORIGINAL witness (1,0),(1,1) of simple R(z0,z1)=[z0=1] decodes the same pre-signature in three independent toy scopes, checks every signature coordinate's accepted alternate produces an explicit hash collision, and asserts a complete correct signature/verifier relationship. Two runs gave byte-identical outputs. The alternate-signature test hash is *intentionally weak*. Independent local-only Python SHA-256 Lamport/source checker also passed 393261 algebraic assertions twice, reproducibly; it is not the GitHub checker and cannot substitute for a QPT hardness proof. Offline archive of longer proof and Python tests is local-only.

**Exact remaining equation:** For arbitrary hard TRUE ORIGINAL x, arbitrary QPT A and the FULL joint public view,

Pr[A outputs sigma_* before having an ORIGINAL witness] <= Pr[Ext^A outputs ACTUAL w: R_x(w)=1] + Adv_QPT(independent SOURCE break) + negligible.

No such Ext, independently justified full SOURCE hardness assumption/reduction, jointly instantiated LWE opening+challenge simulator, arbitrary-FALSE full-public simulator, private source selective openings, multiple hard TRUE branch theorem, malicious N-of-N/abort/data availability proof, practical parameters, or native Bitcoin PQ output is provided. The new theorem reduces only the ALTERNATIVE SIGNATURE part of unauthorized native acceptance to independent QPT strong unforgeability; it does not solve source recovery.