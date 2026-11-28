# XNAR — XOR noise amplification does NOT repair GOIL false-source release

**Offline research checkpoint XNAR-2026-11-01-T05. STATUS: NO POSITIVE SECURE WKEM ADVANCE.** This is a new exact counterexample to one attempted repair, not a new generic witness-encryption solution.

Predecessor: GOIL at blob `b77d79ce786dab5342bfee4a8c4dfb74cce5e0d3`, PR #1 starting head `52b88ba2f94e6510bade88da413164d9dcac6e7f`, last substantive ordinary comment 6555798646. The CQPM/CSQL local repairs were also insecure. All work was offline.

## Attempted concrete Build/Lift

For an arbitrary Boolean ORIGINAL verifier V_x(W), retain GOIL's public one-hot compiler `M_x p=b_x` with N Boolean wires, `p_(i,0)+p_(i,1)=1`, and `||p||_1=N` for every genuine one-hot p. The witness-free classical builder samples public B0, publishes `A=B0 M_x, t=B0 b_x`, and generates a genuinely correlated native signing key/capability K and public checking key vk. Bind the ORIGINAL relation, x, claim/UTXO, challenge branch, anchors/window, signing domain and context. For C independently generated shares, sample C−1 uniform 512-bit strings and set the last share to their XOR with K. For every b-bit packed share symbol m independently sample `s <- F_q^d`, `e <- U([-E,E])^(2N)`, `e* <- U([-E,E])`, and publish `beta=A^T s+e`, `tau=t^T s+e*+g*m` modulo q with `g=floor(q/2^b)`. The full public view includes M_x, B0, A,t, all ciphertexts, genuine vk/preauthorizations, aux/context and related capsules. Public off-chain Lift evaluates V_x(W), constructs its one-hot p, decodes each residual `tau-p^T beta`, XORs shares and returns the SAME original K. Large evidence stays off Bitcoin; actual native PQ Bitcoin support is only hypothetical.

**Correctness:** If `g>2E(N+1)`, every valid ORIGINAL witness (including all distinct witnesses) decodes every capsule identically for *every* supported bounded error sample: `tau-p^T beta=gm+e*−p^T e`, `|e*−p^T e|<=E(N+1)<g/2`. This is only a correctness equation, not encryption security.

## Explicit universal FALSE-family counterexample

The unsatisfiable ORIGINAL `w AND NOT(w)=1` has GOIL variables `z=(w,n,y,s1,s2,s3)` and equations `w+n=1`, `y+s1-w=0`, `y+s2-n=0`, `w+n-y+s3=1`, `y=1`. No Boolean w satisfies these, but PUBLIC signed `z=(0,1,1,-1,0,1)` satisfies the linearized equations. Its corresponding p is `(1,0,0,1,0,1,2,-1,1,0,0,1)`. Hence `A p=t` for *every* B0, despite p being invalid. The attacker ignores the official range check and directly computes `rho=tau-p^T beta=gm+S` with `S=e*−p^T e`.

At toy `q=65537,b=11,g=32,E=2,N=6`, the full exact convolution over all `5^13=1,220,703,125` equiprobable error samples yields
`Pr[|S|<16]=1,220,471,875/1,220,703,125=0.99981056`.
This is a **conservative sufficient success event** for every encrypted symbol, not a claim of optimal decryption. For a 512-bit original key encoded in 47 symbols per share, the simple attacker decrypts all shares and XORs the genuine K with probability **at least** `0.99981056^(47C)`; C=2 gives >0.9823 and C=8 gives >0.9312. The independent extended local Python finite-field checker recovered 127/128 complete keys for C=2 and 123/128 for C=8, executing 60,450 assertions twice identically. Its RNG is a deterministic noncryptographic fixture.

**Asymptotic proof:** Pad this FALSE verifier with N−6 independent Boolean dummy variables. It remains FALSE while the same public signed p now has exactly one `(2,-1)` pair and N−1 ordinary one-hot pairs, so `||p||_1=N+2`, `||p||_2^2=N+4`. Let q scale polynomially so `g>2E(N+1)`. With independent uniform centered error coordinates and independent e*, Hoeffding gives

`Pr[one false symbol decodes incorrectly] <= Pr[|S|>=g/2] <= 2 exp(−(g/2)^2/(2E^2(N+5))) < 2 exp(−(N+1)^2/(2(N+5)))`.

For **any polynomially many** T(N) independently encrypted XOR-share symbols, the union bound `Pr[any error] <=2 T(N) exp(−(N+1)^2/(2(N+5)))=negl(N)` applies even without inter-symbol independence. Thus a classical polynomial-time attacker directly recovers the entire precommitted signing capability on a FALSE ORIGINAL statement with probability 1−negl(N), independent of native verification-key correlations and any additional auxiliary public data. Arbitrary QPT adversaries include this classical attacker. XOR amplification cannot repair the linear residual carrier.

**Security boundary:** No false-instance secrecy, no hard-TRUE recovered-key/native-forgery → actual ORIGINAL witness or independent QPT break, no generic full-joint QPT simulator for structured source M_x, no malicious N-of-N setup/abort proof, no SYS/BTC qualified-source completion, and no deployed native Bitcoin PQ endpoint. This theorem concerns XNAR, not all nonlinear/cryptographic WKEM approaches.

**Next equation:** supply a classical-PPT, witness-free `Comp(R_original,x,scope,vk)` and public `Lift(C,W)=K_precommitted` for **every** valid ORIGINAL W with a *nonpublicly reversible* terminal encoding, plus arbitrary-QPT full-view security simultaneously for relation, capsule, genuine checking key, context/auxiliary and related capsules. Any FALSE/hard-TRUE unauthorized key recovery or native forgery must imply an actual ORIGINAL witness or independently justified PQ break, never a SourceOpen oracle or adversary-volunteered representation.

The published `checker.js` is the exact twice-executed Node 22 finite-arithmetic checker; `output.json` is its captured output. A full expanded offline Python/notes archive is local-only. Neither checker demonstrates QPT security or native Bitcoin signatures.
