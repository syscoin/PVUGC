# Run 407 — direct public-watcher conversion of two-client lattice ABE fails

Actual starting head: e987e879948177e8098df4e9fd444b361841c4a2 on syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918, draft and unmerged. Run 406 note Git blob cb5ec5144694669d7134d3759a18972745e1530f. Scoped applicability audit, NOT a new attack against the intended ABE security model or a generic impossibility theorem for local mixing.

Primary 67-page paper: Cini, Lai, Woo, Lattice-based Multi-Authority/Client Attribute-based Encryption for Circuits, IACR Communications in Cryptology 2025. Publisher PDF: https://acris.aalto.fi/ws/portalfiles/portal/173764034/Lattice-based_Multi-Authority_Client_Attribute-based_Encryption_for_Circuits.pdf. Inspected §2.3 (pp.9–11), Defs 6–7 and Fig.5 (pp.21–24), Figs 6–8, Theorem 2 (pp.24–28), and Appendix D (p.67). This was not a complete proof/errata audit; PDF screenshot calls returned Internal Error, but extractable source equations were available.

## Exact algorithm and game

The main Encmain(pp,apk,epk,cid,x1,mu) encrypts one payload mu. Encsub(pp,esk,cid,x2) issues a second *attribute* ciphertext and uses private encryptor key esk=(D,tdD), explicitly SampPre with lattice trapdoor (Fig.6). The second component is not a public second-message encryption of a late witness. The selective game allows only one attribute per designated slot/ciphertext identifier (CID), while Theorem 2 excludes corruption of the designated subencryptor for two-client instances. The stated ROM proof covers classical PPT, not a demonstrated arbitrary-QPT/QROM game.

## Authors' explicit corrupt-subencryptor distinguishing attack

Making esk PUBLIC so permissionless watchers can call Encsub on any witness is insecure for this particular construction. The authors already give the attack in §2.3: both b=0,1 attribute branches occur in the main ciphertext. Ignoring bounded noise, let

Cbar[j,b] = D[j,b]^T Shat[j,b]^T + S(B[j]-bG),
cbar3 = D3^T shat3 + S*v + g*mu.

A holder of trapdoor tdD finds short nonzero t with D*t=0. Hence u_b=t^T Cbar[j,b] ≈ (t^T S)(B[j]-bG). Subtracting u_0-u_1≈(t^T S)G exposes the shared source mask a=t^T S after public gadget inversion. Then t^T cbar3-a*v≈(t^T g)*mu, allowing the paper's shortness test to distinguish mu. No ORIGINAL relation witness is used. This is the authors' attack on corruption, specialized to the proposed public-esk conversion, NOT an attack on the scheme when esk is kept secret.

Keeping esk secret for post-setup witness admission requires an online issuer, violating the intended liveness model. One pre-issued x2 at a CID cannot represent any arbitrary later w; multiple x2 for the same CID lie outside the proof. Appendix D explicitly derives MI-ABE => WE and explains that restricting each CID to one attribute circumvents the WE implication. The Run 406 desired second-slot oracle would require a DIFFERENT public algorithm and independently justified security.

Executed compact deterministic JS checker: 900 noiseless finite modular fixtures, 1800 no-witness payload recoveries, prime q=17,257,65537 and dimensions n=2,3,4. These checks are only conditional mask-cancellation algebra; they do not implement TrapGen, bounded lattice noise, LWE hardness, signatures, QROM, or concrete parameters. An independently executed longer Python checker (45,180 assertions) is preserved in a separate local archive.

Attack taxonomy: seam cancellation, mask/gauge reconstruction, payload fingerprint, no proven multi-capsule protection with compromised encryptor, adaptive same-CID witnesses outside the game, corrupted retained trapdoor, CID replay isolation not arbitrary admission, public verification keys do not repair recovered payload, and a classical corruption distinguisher (therefore QPT) but NO coherent attack on honest ABE.

Handoff: this LWE two-client ABE cannot be claimed as a drop-in public watcher WKEM. A new independently justified public witness-admission encryption mechanism is required. Run 259 supplies binding only after receipt of an accepted complete representation, not recovery-to-ORIGINAL. Full-public false-instance QPT hiding, early true-instance authorization-to-ORIGINAL or independent break, all-witness SAME-K, malicious N-of-N setup, multi-capsule composition, practical resources and conditional native Bitcoin PQ signing remain unproved. Production unchanged, PR draft/unmerged.
