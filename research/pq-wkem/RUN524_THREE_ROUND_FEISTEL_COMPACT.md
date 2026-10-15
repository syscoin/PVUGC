# Run 524 — two opened references recover a three-round nonlinear shared frame

Research-only 2026-10-15. Exact live parent 013e6a81425ccd1b5bc0fd9b7c7dab4395bd4919. Draft syscoin/PVUGC#1. **Scoped falsification, not a secure witness-KEM.**

## Honest model and tested primitive
Classical PPT honest constructor draws independent uniform shared frame keys a,b,c in F=GF(2^n), initializes independent branch signing capabilities K_d, publicly commits each full-state anchor P(K_d,d), and erases a,b,c. A claim with valid ORIGINAL evidence legitimately discloses its K_d to a watcher. Assume two such opened reference anchors supply **full** known semantic input/output pairs (L_j,R_j)->(U_j,V_j), with R_1 != R_2. Public native checking keys and all capsules remain in the attack view. This premise depends on the actual state layout; distinct claim IDs alone do not imply different R.

A proposed compact common frame uses three Feistel rounds:
T=L XOR f(R XOR a); U=R XOR g(T XOR b); V=T XOR h(U XOR c).
Its public nonlinear first function is f(z)=alpha*inv(z) XOR gamma over F, alpha!=0, inv(0)=0. Public g,h are efficiently invertible permutations (the checker uses separate affine inverse maps). Output is P(L,R)=(U,V).

## Exact two-reference attack
For two known pairs set
d=R_1 XOR R_2 != 0,
q=L_1 XOR L_2 XOR g^(-1)(U_1 XOR R_1) XOR g^(-1)(U_2 XOR R_2).
Let u=R_1 XOR a. Eliminating the unknown b from the second round gives
f(u) XOR f(u XOR d)=q, where q!=0 because f is injective.
For u not equal to 0 or d, the inverse-field differential is q=alpha*d/[u(u+d)], so
u^2 XOR d*u = alpha*d/q.
This is **GF(2)-linear**. Its kernel is {0,d} for d!=0, so Gaussian elimination yields at most two regular roots. The exceptions u=0,d are checked separately and satisfy the differential precisely when q=alpha/d. Thus **at most four** candidate u values exist and are enumerable in classical polynomial time.

For each candidate recover
a=R_1 XOR u;
T_1=L_1 XOR f(R_1 XOR a);
b=T_1 XOR g^(-1)(U_1 XOR R_1);
c=U_1 XOR h^(-1)(V_1 XOR T_1).
Test each resulting triple against both reference pairs. The true frame key is in the <=4 candidates.

From the public anchor for a separate ORIGINAL-false target, invert each candidate frame, yielding <=4 possible exact protected capabilities, one guaranteed correct. A random candidate recovers the full false-target seed with probability **at least 1/4**. No target witness, inter-claim switch, chosen-reference oracle, retained setup secret or native checking key is required. Authorized reference releases and honestly erased shared keys suffice. This is classical PPT, therefore available to arbitrary QPT attackers.

## Scope and dependency ledger
This falsifies only an XOR-prekeyed **three-round Feistel shared frame** with first-round public field inversion, publicly invertible g,h, full known reference state pairs, and distinct reference right halves. It does NOT show a break of arbitrary Feistel/PRP/local mixing, independent per-claim frames, opaque partial reference states, or real Syscoin deployment. The full-state requirement matters. Inverse-field differential uniformity is established S-box literature, not an invented hardness result (Bracken–Leander arXiv:0901.1824; Jeong–Koo–Kwon DOI:10.1016/j.ffa.2021.101931). No complete RIO or local-mixing proof audit was performed.

Attack taxonomy: (1) no local seam needed; (2) two opened references synchronize a common frame; (3) inverse differential fingerprint; (4) static multiple capsules; (5) no chosen oracle; (6) honest erasure fails for this shared frame; (7) distinct claim contexts retained; (8) VK optional, can test candidates; (9) classical PPT break, no special coherent quantum attack.

Python extended checker (local-only) executes exact GF(2) elimination, exhaustive 4-/8-bit differential algebra (240+65,280 pairs), 950 deterministic two-reference trials through 16 bits, eight independent 4096-key brute comparisons, two byte-identical executions. Published JS compact checker independently checks all 240+65,280 differential pairs and 256 deterministic two-reference fixtures in 4-/8-bit fields. Toy tests corroborate algebra, not 128-bit security.

Run 519's atomic-commutator identity and Run 259's supplied-complete-representation source binding retain only their existing scopes. Full-public-output QPT release security, arbitrary unauthorized native authorization -> ORIGINAL extraction, honest/malicious N-of-N setup+abort/erasure, multi-capsule security for an actual surviving mixer, concrete parameters, conditional P2MR/native SLH and a verified Bitcoin claim/challenge graph remain **UNPROVED**. No production changes, PR remains draft/unmerged, stopping condition unmet.
