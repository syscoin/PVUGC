# Native preauthorization transcript under SOURCE key: restricted QPT composition

**2026-10-31. Narrow positive proof, NOT a generic NP witness-KEM.** The earlier exact source note (head e98b7d9014f003e62d42b53c61e34fb791c93438; README blob 930334ec2b58e8f9722e1fe1c8608c220e9aa6d8) allowed only public/vk-computable auxiliary data. This result admits **real secret-key-dependent native signatures on public ciphertext-dependent messages** inside the *joint* SOURCE public view, with the same native sk hidden by every protected ciphertext. The full derivation and stronger local Lamport-Merkle mock are additionally available in the local archive described in provenance.

## Exact honest distribution, relation and all-witness release

For odd prime q, take A uniform in F_q^(d×n), t uniform in F_q^d. The restricted ORIGINAL relation is R((A,t),w) = [w binary length n AND A w = t mod q]. Generate (sk,vk) by an honest classical-PPT native signature key generator. Let κ be the canonical encoding of sk, with T protected bit encryptions across polynomially many related unopened capsules sharing (A,t,sk,vk). Each independently samples s_i uniform in F_q^d, e_i in χ^n and e*_i in χ, with independent bounded errors |e| ≤ B. The **actual** source-dependent capsule entries are

\[
\beta_i=A^\top s_i+e_i,\qquad
\tau_i=t^\top s_i+e^*_i+g\kappa_{j(i)}\pmod q.
\]

The full public view includes relation identity, (A,t), capsule ciphertexts, the native checking key vk, claim/UTXO, challenge branch, scope and source anchors/window, related-capsule digests, publicly computed auxiliary data and genuine native signing transcripts. A classical-PPT policy may adaptively choose each preauthorization message based on all prior public objects and authentic signatures, then honestly Sign(sk,message). The policy must NOT read the master, encryption coins, protected witness openings or any other secret-dependent data, and must never sign the challenge message. All preauthorization native messages have a distinct 0x00 prefix from the 0x01 challenge-path message, giving exact separation before any hashing. This is one-time setup signing, not an online release authority.

For every valid binary ORIGINAL witness w, independent of which other witnesses exist,

\[
w^\top\beta_i-\tau_i=w^\top e_i-e^*_i-g\kappa_{j(i)}\pmod q.
\]

Because |w^T e_i-e*_i| ≤ B(n+1), if g > 2B(n+1) and 2(g+B(n+1)) < q, nearest-center decoding produces every bit of the **same precommitted native sk**. Different valid witnesses may have different state vectors. The original evidence and the mathematical release algorithm remain off chain; no Bitcoin NP verifier is presumed.

## Exact restricted QPT theorem

Let p = Pr_uniform[(A,t) admits some binary w] ≤ δ = 2^n/q^d. Define F as the uniform (A,t) distribution *conditioned on FALSE*. Let Adv_DLWE bound standard nonuniform-QPT decisional LWE for a uniformly random matrix M^T=[A^T;t^T] of size (n+1)×d, an independent uniform s of length d, and errors χ^(n+1). Assume a native signature scheme nonuniform-QPT EUF-CMA secure with **classical-message** signing oracle queries, and honest classical keygen/sign, including enough signing queries to implement the setup policy.

For any nonuniform-QPT adversary processing the ENTIRE classically generated public view (possibly with coherent internal quantum computations), producing a fresh valid challenge-domain native signature not among the signer-oracle queries satisfies

\[
Pr_F[\mathrm{fresh\ native\ forge}]
\le p+\sum_{i=1}^{T}\mathrm{Adv}_{DLWE}(\mathcal B_i)
+\mathrm{Adv}_{native\ EUF-CMA}(\mathcal B_{\rm sig})
\le\delta+T\epsilon_{\rm LWE}+\epsilon_{\rm sig}.
\]

The same bound applies to recovery of the actual canonical sk if the attacker can use it to sign a fresh challenge message under vk. No attacker-supplied representation or SOURCE-opening oracle is assumed. This is NOT a concrete 128-bit security estimate, not a proof for adversarial FALSE, and not hard-TRUE extractability.

**Proof, with all correlations:** (1) Uniform source conditioned on FALSE differs in exact total variation by p from unconditioned uniform. Generating the *real native key, real source-dependent capsules, real adaptive native signatures, and public aux* is a shared stochastic kernel, so total variation and its bound survive any QPT postprocessing. Efficient FALSE rejection sampling is unnecessary. (2) Replace each protected ciphertext in a straight-line hybrid. The LWE distinguisher receives the actual random challenge matrix M^T and one LWE/random vector y; it sets that vector's last coordinate translation to gκ_i, samples other ciphertexts according to their hybrid positions and **generates genuine sk/vk** itself. After the challenge-dependent public capsules are assembled, it runs the prescribed policy and signs all adaptively selected public messages with its known sk. This gives the COMPLETE native-key/signature/capsule correlations in both hybrid distributions. Every hop is ordinary QPT LWE; there is no marginal-pad-only assertion. (3) In the final all-uniform-ciphertext game, a native EUF-CMA forger receives challenger vk but NOT sk, samples uniform A,t,capsules, and generates the same adaptive policy transcript using its **classical native signing oracle**. The forger relays the adversary's signature on the separate, never-queried challenge-domain message. This is an ordinary fresh-message EUF-CMA break. The reduction is straight-line without rewinding or automatic classical-to-QPT lifting.

The signed-message policy must be classical-PPT and use only public history to select messages, while native signatures are actual secret-key-dependent outputs. Quantum signing-oracle superposition access, secret-dependent external aux beyond these signatures, and selective opening of any same-key capsule/witness/encryption randomness are EXCLUDED. No preauthorization message can be reused as a challenge signature in this theorem; proving that Bitcoin path/SIGHASH encodings enforce this is a separate graph task.

## Deterministic adversarial-FALSE counterexample and missing original reduction

For chosen FALSE A=[1],t=[3], w in {0,1} never satisfies Aw=t. But public nonbinary z=3 yields

\[
z\beta_i-\tau_i=3e_i-e_i^*-g\kappa_i.
\]

At B=1,g=21 this deterministically decodes the encrypted master bit for **every honestly sampled error value**, not just zero noise. Thus the real source has unauthorized nonwitness key recovery (and hence native signing) even with fully legitimate native preauthorization signatures. This must NOT be obscured by the restricted random-FALSE theorem. In the low-density regime δ negligible, planted TRUE sources are statistically at least 1−δ away from uniform, so this hybrid does not prove hard-TRUE security.

Still MISSING: generic-NP classical-PPT witness-free Comp(R,x,context,vk), public Lift for all ORIGINAL witnesses and the same committed key, cryptographic rejection of arbitrary nonwitness recovery, and a truly instantiated full-joint QPT simulator with arbitrary FALSE and unauthorized hard-TRUE key/native forgery → actual ORIGINAL witness or independently justified QPT break. One-honest N-of-N setup/MPC, bypass-edge exclusion, erasure, abort, pre-funding availability, SYS/BTC AuxPoW/coinbase tag ancestry qualification, reorg/censorship assumptions and an actual no-EC-path native PQ Bitcoin endpoint are not established.

## Executed compact checker (exact source and output)

The Python script below was executed twice locally, giving 3,589 passing explicit assertions and byte-identical output. It tests 3×512 source-dependent encrypted bits; two distinct valid ORIGINAL witnesses; a true-key-correlated adaptive signing-oracle interface and a last-game uniform-ciphertext oracle transcript; and all 512 nonwitness key bits recovered on chosen FALSE. The oracle mock is deliberately NOT a publicly verifiable PQ signature scheme; the separate offline extended Python archive checks native toy Lamport-Merkle verification (105 explicit assertions twice), while the symbolic proof above is the security argument. **Neither checker tests QPT hardness.**

~~~python
#!/usr/bin/env python3
# Compact exact algebra/signer-oracle interface checker; NOT QPT or native security.
import random, hashlib, json
r=random.Random(20261031+1157); checks=0
def ok(x):
    global checks
    checks+=1
    assert x
def dot(a,b): return sum(x*y for x,y in zip(a,b))%257
def mv(A,w): return [dot(row,w) for row in A]
def E(A,t,k):
    s=[r.randrange(257) for _ in A]
    e=[r.randint(-1,1) for _ in range(len(A[0])+1)]
    return ([sum(row[j]*s[i] for i,row in enumerate(A))%257+e[j] for j in range(len(A[0]))],
            (dot(t,s)+e[-1]+21*k)%257)
def D(w,C):
    out=[]
    for v,t in C:
        z=(dot(w,v)-t+128)%257-128
        out.append(0 if abs(z)<abs(z+21) else 1)
    return out
K=[r.randrange(2) for _ in range(512)]
A=[[r.randrange(257) for _ in range(6)] for _ in range(3)]
for row in A: row[1]=row[0]
w1=[1,0,0,0,0,0];w2=[0,1,0,0,0,0];t=mv(A,w1)
ok(mv(A,w2)==t)
C=[[E(A,t,b) for b in K] for _ in range(3)]
for cap in C:
    for w in (w1,w2):
        z=D(w,cap)
        for i in range(512):ok(z[i]==K[i])
# Signer oracle is an opaque classical function of hidden K.
# Policy receives public data, previous signatures and callback only.
master=bytes(sum(K[i+j]<<(7-j) for j in range(8)) for i in range(0,512,8))
vk=hashlib.sha256(master).hexdigest()
def oracle(msg):return hashlib.sha256(master+b'|'+msg).hexdigest()
def policy(caps):
    prev='start';out=[]
    digest=hashlib.sha256(json.dumps(caps,sort_keys=True).encode()).hexdigest()
    for i in range(3):
        m=('P:utxo:4|scope:sys|'+digest+'|'+str(i)+'|'+prev).encode()
        sig=oracle(m);out.append((m,sig));prev=sig
    target=('C:utxo:4|scope:sys|'+digest+'|'+prev).encode()
    return out,target
real,target=policy(C)
ok(len(real)==3 and all(m!=target for m,_ in real))
uniform=[[( [r.randrange(257) for _ in range(6)],r.randrange(257)) for _ in K] for _ in range(3)]
sim,simtarget=policy(uniform)
ok(real[0][0]!=sim[0][0] and all(m!=simtarget for m,_ in sim))
# Honest randomly noisy chosen FALSE: A=[1], t=[3], binary W impossible.
Ab=[[1]];tb=[3]
ok(all(mv(Ab,[w])!=tb for w in [0,1]))
false=[E(Ab,tb,b) for b in K]
attack=D([3],false)
for i in range(512):ok(attack[i]==K[i])
ok(hashlib.sha256(bytes(sum(attack[i+j]<<(7-j) for j in range(8)) for i in range(0,512,8))).hexdigest()==vk)
print(json.dumps({'checks':checks,'valid_original_witnesses':2,'related_capsules':3,'true_key_bits_recovered':3072,'false_public_nonwitness_bits_recovered':512,'adaptive_public_signer_transcript':3,'last_game_oracle_interface':True,'native_signatures':'hash-based opaque oracle mock, not a public verification scheme'},sort_keys=True))

~~~

Captured output from two identical runs:

~~~json
{"adaptive_public_signer_transcript": 3, "checks": 3589, "false_public_nonwitness_bits_recovered": 512, "last_game_oracle_interface": true, "native_signatures": "hash-based opaque oracle mock, not a public verification scheme", "related_capsules": 3, "true_key_bits_recovered": 3072, "valid_original_witnesses": 2}
~~~

Provenance: syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918, starting SHA e98b7d9014f003e62d42b53c61e34fb791c93438, latest substantive prior comment 6544370124. Local commands: python checker_compact.py > compact1.json; python checker_compact.py > compact2.json; cmp compact1.json compact2.json. Source SHA256 ccc2a94831a7c0acccfd00add733dd522143f4250642d75e84e60fe2f8528d57; captured output SHA256 7c05089b686901a88a01776902b00870dd00a6e2174b575d73ad9c5308de32a4. Extended offline research archive SHA256 419dcbb82cbcbaddfc552ce315a43aaa5878172cf34c09b8fd0ba0372d8c3543 (local-only unless separately published). External literature research: none. Independent agents: none. No on-chain tests, deployed Bitcoin functionality, or claim of complete PQ WKEM.