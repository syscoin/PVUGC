# R306 — Source-issued SHA preimage labels (NONQUALIFYING)

## Exact continuation and source discipline

One bounded offline continuation of R305 (blob `3cd7c1c543d9361490a88afe512adcd46f0481db`) and the R303 hidden-label attempt, starting PVUGC PR #1 head `086fc5df8cdb8459d70d52d401f7f679e127e6bf`, draft branch `research/pq-wkem-validation-20260918`. Inspected current Core #609 PR metadata: head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no Core tests/deployment claim. Last substantive ordinary PR comment remains R225 #6796383617. No web, external literature, other repo writes, independent agent, or production changes.

The target remains a single frozen, claim-safe native cancellation capability from **any** qualified ORIGINAL witness: strictly more exact same-anchor BTC work, finite authenticated refutation of the particular burn authorization, or qualified Syscoin semantic inconsistency / exact asserted-wrapper tag fault. Preserve all x_W claim/UTXO, amount, recipient, anchor/window, actual ancestor at h_rel, contextual modern chain ID, exact canonical 41-byte tag, distinct AuxPoW chain-root, source-depth, deadline/reset, capsule/message/VK bindings. An exact malformed parent wrapper cannot borrow LC admission from a different valid wrapper of the same child (R304). R225 native fixed-outpoint activation portability remains unresolved. N-of-N setup is distinct from permissionless challenges.

## Actual candidate Build/Open, and source issuance gap

Take a 256-bit surrogate S for the frozen safe cancellation authorization (the checker does **not** use a native signature), x=x_W, and domain-separated SHA256 hashes Y, K. Classical Build samples independent `r_i <- {0,1}^lambda` for i=1..m, and publishes

```
y_i = H("R306-Y" || x || r_i)
c_i = S XOR H("R306-K" || x || r_i)
C=(x,{(y_i,c_i)},VK,context).
```

Proposed public Open first verifies **the complete** ORIGINAL R(x,w) including relevant authenticated sources, BTC best-chain anchor/reorg and exact work, burn nonmembership/refutation/execution where applicable, and contextual Syscoin tag/height/ancestry/LC. Let T_x(w) be the finite list of actual source-carried token-size strings from its authenticated bytes. If some token t has H("Y"||x||t)=y_i, it returns c_i XOR H("K"||x||t), provided that this is the fixed, claim-safe native authorization. Honest synthetic control t=r_i opens exactly S, independently of i. Another t colliding under Y need not reproduce the K pad.

**Nothing in the postactivation Core AuxPoW rules, canonical tag, Bitcoin headers, native Merkle branches, or independently generated future certificates furnishes a setup-selected r_i.** Merely checking R before attempting decryption does not issue it. Therefore this is only a syntactic polynomial Build/Open, NOT a correct source-dependent ORIGINAL one.

## Independent-source issuance lemma and exact quantifiers

For the *restricted control distribution* in which any qualifying future certificate exposes at most d independently uniform lambda-bit token candidates independent of the m setup labels,

```
Pr[one certificate contains any exact r_i] <= m*d/2^lambda.           (1)
Pr[two independent certificates both contain an r_i]
     <= (m*d/2^lambda)^2.                                              (2)
```

Proof: condition on the setup set A of <=m labels. A single independent list hits it with probability at most |A|d/2^lambda by the union bound; two independent lists yield the square conditional on A, hence after averaging. This is an *honest every-witness completeness* failure for this specific issuance model, not a general security bound, a QPT theorem or a statement about all correlated real histories. When witnesses share a public claim-prefix ancestor/root, their candidate tokens are correlated; a source common value already known publicly would instead cause immediate FALSE/public recovery if used as a pad. Under lambda=256,m=16,d=64, bound (1) is 8.843436600416711e-75. Polynomially many secret labels cannot make arbitrary independent future source bytes deliver a chosen preimage.

A malicious miner adapting to public y_i must be modeled separately: searching for an r_i is a preimage problem (and does not establish best-chain membership); neither (1) nor (2) is an adversarial QPT mining bound. No claim of a quantum lifting or concrete-SHA extraction proof is made.

## Joint-public release/security attempt and repairs

* In an idealized *classical* two-domain random-function distribution, masks H_K(r_i) are independent uniform conditional on never revealing or querying their hidden inputs. Thus c_i are uniform even when S is correlated with the public native VK and independent sibling information. This is conditional hiding **beyond** native VK/auxiliary disclosure; not a full-public QPT theorem, and it is vacuous for source release because actual honest witnesses cannot obtain r_i.
* If the source object publicly carries an r_i, any observer extracts S before a qualified *new* challenge. If a malicious source producer retains r_i before publishing an admitted certificate, the source-coin-retention adversary extracts early. Core source validation cannot revoke an already exposed signature.
* Requiring two distinct conflicting certificates to expose two independently hidden labels lets Build use H_K(r_a||r_b), but still lacks an issuer for either. It also cannot replace single-certificate finite burn refutations in the ORIGINAL OR relation.
* Truncated target/prefix matches can be generated by source mining, but do not reproduce the frozen pad for different full preimages; using the public prefix as pad immediately leaks S. This retains the known R237 target-prefix regression rather than declaring a new construction.
* A new source signer, secret-keeping issuer or consensus rule requiring these preimages would change the source model and is excluded. Capsule commitments authenticate bytes, not create previously unknown preimages.

This gives a precise **issuance/completeness trilemma for this label-lock family**, not an impossibility theorem for arbitrary nonlinear source-specific hash-only WE or an independently instantiated ORIGINAL security proof. It identifies why R303-style private labels cannot simply be "sourced" from SHA/AuxPoW.

## Executed local evidence and exact next equation

Python 3 stdlib `checker.py` built real SHA256 hash commitments and ciphertexts against *synthetic*, not admitted Bitcoin/Syscoin, source token lists. Two separate runs each executed 13 assertions and returned byte-identical JSON SHA256 `67d587ad5af44e19639599d9ba7d6cbf3b72b111f60eaae7394d6f1b5dc9c952`. Checker SHA256 `144c4ba8048bebf1b69279d0302471cd12e2c60136eb29582570ed14f4ab5734`. A 12-bit independent-token control sampled 4000 trials (m=16,d=64): 833 one-certificate hits, 204 two-certificate hits, versus independent benchmarks approximately 0.22158 and 0.04910. A 256-bit control sampled 400 trials with no hit; (1) rather than the sample supports the stated mathematical bound. Exact setup-token forced opens, public-label premature recovery, 8-bit-prefix nonconvergence and two-label nonissuance were checked. No real Core/Bitcoin work tests, best-chain admission, native SLH signing or quantum execution were performed.

Full derivation, executable checker, paired JSON, and provenance are in local `R306_source_label_issuance_20261115.tar.gz`, archive SHA256 `16ab331fe58bc9f5fea9978ee20a826c5f22af2877a0285ac9dda58da38b8870`, NOT part of this PR file. No assumptions about sandbox persistence.

**Exact missing ORIGINAL equation:** construct classical PPT `Build_inc(x_W,sigma_cancel)` and publicly executable `Open_inc(C,w)` producing the SAME frozen claim-safe capability for **every** authenticated original-source witness without prior issuance of setup secrets, and prove full-public FALSE plus unauthorized hard-TRUE QPT recovery or accepted native forgery implies an **actual qualifying ORIGINAL certificate** or independent PQ hash/native break, under malicious setup and correlated capsules. No such issuer or nonlinear release mechanism is constructed here. **NONQUALIFYING; no ordinary PR progress comment, deployment, notification or automation stop warranted.**
