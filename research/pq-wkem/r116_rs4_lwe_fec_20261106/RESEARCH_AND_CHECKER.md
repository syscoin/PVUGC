# R116 — Four-bit Reed–Solomon ordinary-LWE release (restricted credentials)

Run R116-FOUR-BIT-RS-LWE-CAPABILITY-20261106. Starting verified syscoin/PVUGC#1 open/draft/unmerged branch research/pq-wkem-validation-20260918 at 85e6a368df717c4a25e3dcd9d34a2be54ca4ceaa. Selected predecessor R115 note exact blob 4e36cc4261d65127b37b0b135e9d5efba02cf7be. The R111, R112 and R114 generic-ORIGINAL source candidates remain rejected. **This is a real restricted ciphertext-efficiency improvement, NOT a generic NP WKEM or a quantum-hardness result.**

## Concrete release, including source and full-public data

Retain the actual R115 source: uniform A in F_q^(m×d), q=65521,m=2000,d=256; independent honest S_ij uniform F_q^(d×64), E_ij uniform [-3,3]^(m×64), with B_ij=A S_ij+E_ij (mod q) for every capsule/credential pair. The restricted ORIGINAL credential predicate verifies actual bounded-error (S',E') pairs and a qualifying CNF clause policy. It is NOT an arbitrary NP-to-LWE compiler. A nonuniform QPT malicious public source generator may choose arbitrary dependent malformed B after seeing A and ALL honest B, retaining arbitrary quantum advice, but BEFORE independent ciphertext coins. Honest setup and encryption are classical PPT. No SourceOpen oracle is invoked.

R115 preauthorizes one fixed native signature sigma_j on a domain-separated message binding original restricted relation identity, claim/UTXO, branch, anchors/window, capsule, N-of-N graph, challenge path, context and intended native VK. Its secret 20,192-bit seed T consists of TWO independent genuine scalar-LWE pad source pairs (s_h,e_h), s uniform F_q^256, e uniform [-3,3]^2000. Two b_h=A s_h+e_h conceal the 7,856-byte native signature once through a public q-ary Dsig. Uniform XOR-sharing distributes T among CNF clauses. Every authorized path chooses its own credential per clause and reconstructs the same T, even with distinct witness states. Preserve all of R115's native VK, public claim/context, related capsules, Dsig, manifest J, checking keys CK and auxiliary data, computed entirely as public PPT processing of actual challenge bytes and independent simulatable coins. No secret-dependent checking receipts or proof oracle are allowed.

**New ciphertext encoding:** Encode EACH 20,192-bit CNF share as 2,524 bytes, append four zero bytes to 79 groups of 32 bytes. For every one of 32 byte lanes independently, interpolate the unique degree-below-79 polynomial over GF(256)=F_2[z]/(z^8+z^4+z^3+z+1) at evaluation points 1..79 and add its evaluations at 80..85. This systematic RS(85,79) code has minimum distance 7 and corrects ANY three erroneous whole 32-byte groups, even when all 32 bytes in those groups are corrupted or jointly correlated.

For each of the 85 coded groups under each credential occurrence, split its bytes into 64 four-bit symbols mu in {0,...,15}. With NEW, INDEPENDENT exact uniform bounded-L1 coins r in D={r in [-3,3]^2000: ||r||_1≤2729}, publish (u,v)=(Aᵀr, B_ijᵀr+4095 mu) mod q. Cyclic 16-symbol codepoint spacing is 4095 or 4096. Each ciphertext remains (256+64)*2=640 bytes. Source-share data shrink from 158*640=101,120 to **85*640=54,400 bytes per credential occurrence**, a **46.2025% reduction**, while A/B key sizes and Dsig remain unchanged.

**Off-chain Open:** Validate the actual restricted source witness, decrypt 85 LWE ciphertext groups under its actual bounded-error secret with z=v−S'ᵀu, nearest-decode 64 nibbles per group, run a real RS(85,79) bounded-distance decoder on each of 32 byte lanes, reject uncorrectable groups/padding, reconstruct the 20,192-bit clause shares then XOR to T, regenerate R115's pad and exactly precommitted signature, and verify under the challenge-bound native VK. Bitcoin runs no original NP verifier, VM, proof, PCP or BitVM dispute.

## Simultaneous correctness for ALL accepted credential witnesses

This is **overwhelming-probability setup/evaluator correctness**, not R115's zero-error-on-every-coin-tape correctness. For all B, including malicious B selected after public A, two accepted bounded short-error representations would have a nonzero Δs with AΔs=−Δe and Δe in [-6,6]^2000. For each fixed nonzero Δs, uniform AΔs has uniform independent entries. Union-bounding ALL (q^256−1) differences gives an unconditional global event
 δ_unique ≤ (q^256−1)(13/q)^2000 < 2^(-20502.54).
Consequently outside this event **every B at once has at most one accepted bounded source error representation per column**. A QPT adversary who selects an accepted witness after inspecting ciphertexts cannot switch to a special alternative error vector; malicious/related public key dependence does not alter the bound.

R110's EXACT uniform coin law is proposed iid with mass proportional to t^|r_i|, t=13/18, with r_i∈[-3,3], and accepted with indicator L1≤2729 times probability t^(2729−L1). Put Z=1+2(t+t²+t³) and |D|=sum_{h≤2729}[z^h](1+2z+2z²+2z³)^2000. Acceptance is p_acc=|D|t^2729/Z^2000=0.030994262341084114..., and the accepted r is exactly U(D). Conditional sign symmetry gives for ANY bounded |e_i|≤3 chosen before r:
 Pr(|eᵀr|≥h) ≤ (2/p_acc) exp(−λh) [(1+2 sum_{a=1}³ t^a cosh(3aλ))/Z]^2000.
For four-bit cyclic minimum spacing 4095, a nearest-codepoint error requires |eᵀr|≥2048. Fixed λ=1/25 gives **p_symbol <2^(-51.6147)**. This is a conservative actual Chernoff bound, not a Gaussian heuristic or presumed quantum hardness.

All 64 symbols within a group share r; they may fail **fully coherently/correlated**. Union-bound only: p_group≤64 p_symbol<2^(-45.6147). Distinct RS groups use INDEPENDENT r conditional on all A,B, malicious quantum advice and the uniquely fixed accepted E; do not multiply failure probabilities of different bytes within a group. With distance 7, at least FOUR whole-group errors are needed for any RS failure:
 p_occ≤binom(85,4) p_group^4<2^(-161.5094).
For 16 capsules ×16 credential occurrences, union across all 256 occurrence codewords plus the global-A bad event gives **simultaneous failure for ANY accepted restricted witness/path ≤2^(-153.5094)+2^(-20502.54)**. This explicitly handles adversarial postview witness selection and all 32 byte lanes. The entire probability statement uses the stated setup order and conditional independence; it does not guarantee correct decoding on every possible coin tape. Strict all-tape correctness users must keep R115.

## Full-public ordinary-QPT-LWE/native-forgery proof boundary

Adversaries arbitrary nonuniform QPT with coherent joint processing and retained quantum advice; queries/reveals classical. Preserve the R115 capsule-local independent-key, malicious-key correlation and related-capsule selective-opening interface: unqualified final corruption set; no opening of target protected-cut honest credentials/coins, no target native signing-oracle query, no non-simulatable secret-dependent CK/Aux, and all off-target native messages distinct. Honest keys and all public checking/context/auxiliary outputs are simulated **jointly** in the same transcript; not an assumption of marginal pad hiding.

Select a target and an honest-only unsatisfied CNF clause cut. For each newly protected 85-group ciphertext, embed a GENUINE ordinary QPT scalar-LWE-PKE challenge encrypting the real RS share or zero under its actual honest B. The simulator knows both plaintexts and all unchallenged key material but not challenge S/E or r; construct *all* other public source keys, malicious chosen B and retained advice, all sibling ciphertexts, Dsig, J/CK/Aux, original restricted statement, native VK and related capsules from those actual challenge bytes. Once the protected whole XOR clause is zeroed, all other clauses remain jointly independent of T and deterministic RS parity preserves this independence. Then embed TWO genuine ordinary scalar QPT decisional-LWE pad challenges to replace b_h=A s_h+e_h by uniform. In this terminal hybrid Dsig is uniform, allowing an independent native QPT-EUF-CMA challenger with no signing query on the target challenge message. Fresh accepted native target signature implies a native QPT forgery, with usual polynomial target/cut/group hybrid losses. No quantum rewinding, assumed SourceOpen, generic WE, iO or disguised KEM release assumption is used.

This changes neither the q,d,m,ell, exact source error law, exact coin distribution, nor ordinary scalar-QPT-LWE security assumption from R110/R115; only the message alphabet and public deterministic RS encoding change. When the 64 B source columns are hybridized to uniform using actual scalar QPT LWE challenges, the map r↦(Aᵀr,Bᵀr) is universal over F_q^320 for distinct supported r, yielding ½√(q^320/|D|) statistical leftover error PER group. For 16×16×85 groups the total uniform-source statistical bound is <2^(-149.18), better than R110's 158-group budget. These are statistical errors, NOT calibrated QPT LWE work factors. Same native EUF assumption, full-public auxiliary simulability, malicious ceremony and corruption restrictions as R115; the cost is the explicitly quantified negligible correctness failure.

## Unresolved ORIGINAL requirement and original security model

This is NOT an arbitrary ORIGINAL-NP/SYS-BTC source compiler. Missing: classical-PPT Comp(R_original,x;coins) producing a genuine witness-dependent LWE source, source openings and jointly simulatable full capsule/CK/Aux/context/verification key/related capsules such that EVERY valid ORIGINAL witness recovers ONE precommitted capability; arbitrary unauthorized hard-TRUE QPT exact capability recovery or accepted target native forgery must imply an ACTUAL ORIGINAL witness or independent QPT hardness break, without adversary-volunteered representation. Generic fixed-FALSE full-public security is separate and unsolved. The R111/R112 invalid short near-keys and R114 public Boolean quotient extraction are regression failures, not repairs.

No practical calibrated 128-bit QPT parameter security is claimed. N-of-N preauthorization with one honest excluding bypass edges, erasing secrets, audit of signatures/DA before funding, malicious abort, one-of-N watcher liveness, enforceable timely admissible challenges, original SYS/BTC headers/AuxPoW/coinbase tags/height/ancestor/lag/window/fork/censorship rules and hypothetical no-EC-key-path P2MR-like native SLH-like signature output remain conditional. AuxPoW work alone is not best-chain membership; no arbitrary Bitcoin censorship/detection guarantee, new opcode, online release committee or production deployment.

## Exact executed checks and provenance

The actual embedded JavaScript checker below uses exact BigInt counting of the R110 source coin support, Chernoff/uniqueness/LHL arithmetic, all 65,520 safe codepoint/noise cases, true GF(256) systematic evaluation parity coefficients, and randomized minimum-distance checks. Its unedited JSON is appended. Independent LOCAL-ONLY Python 3+NumPy checker_fec.py executed 65,814 assertions with a complete RS(85,79) 32-byte-lane Berlekamp–Welch decoder, 0/1/2/3 deliberately corrupted entire 32-byte groups, high-precision coin/Chernoff proof and actual small uniform-A LWE encryption under distinct source credentials. Local RESEARCH.md contains expanded derivations and captured-fec.json the exact output. This source and output are not called GitHub-published. No external internet/literature research or independent agents.

## Exact executed JavaScript checker

```javascript
(function checkR116(){
 const q=65521,m=2000,d=256,ell=64,L=2729;let a=0;const ok=(b)=>{a++;if(!b)throw Error("assert "+a)};
 let c=Array(L+1).fill(0n);c[0]=1n;
 for(let i=0;i<m;i++){let n=Array(L+1).fill(0n);for(let j=0;j<=Math.min(3*(i+1),L);j++){n[j]=c[j]+(j>=1?2n*c[j-1]:0n)+(j>=2?2n*c[j-2]:0n)+(j>=3?2n*c[j-3]:0n);}c=n;}
 let card=c.reduce((x,y)=>x+y,0n);
 const bits=card.toString(2), log2N=bits.length-53+Math.log2(parseInt(bits.slice(0,53),2));
 const t=13/18,Z=1+2*(t+t*t+t*t*t),logAcc=log2N+2729*Math.log2(t)-m*Math.log2(Z);
 const lambda=.04,M=1+2*[1,2,3].reduce((s,j)=>s+t**j*Math.cosh(3*j*lambda),0);
 const logP=1-logAcc-lambda*2048/Math.LN2+m*Math.log2(M/Z);
 const binom=(n,k)=>{let x=1;for(let i=0;i<k;i++)x=x*(n-i)/(i+1);return x};
 const logFail=Math.log2(binom(85,4))+4*(logP+6)+8;
 const logUnique=d*Math.log2(q)+m*(Math.log2(13)-Math.log2(q));
 const logLHL=-1+.5*(320*Math.log2(q)-log2N)+Math.log2(256*85);
 ok(Math.abs(log2N-5445.079378072014)<1e-5);ok(logP<-51.6);ok(logFail<-153.4);ok(logUnique<-20000);ok(logLHL<-149);
 const codes=Array.from({length:16},(_,i)=>4095*i);
 function centered(x){return ((x+32760)%q+q)%q-32760}
 function dec(z){let best=0,dist=1e9;for(let i=0;i<16;i++){const dd=Math.abs(centered(z-codes[i]));if(dd<dist){dist=dd;best=i}}return best}
 for(let s=0;s<16;s++)for(let e=-2047;e<=2047;e++)ok(dec((codes[s]+e+q)%q)===s);
 function gf(x,y){let z=0;while(y){if(y&1)z^=x;x<<=1;if(x&256)x^=0x11b;y>>=1}return z}
 function inv(x){for(let y=1;y<256;y++)if(gf(x,y)===1)return y;throw Error("inv")}
 let parity=[];
 for(let xp=80;xp<=85;xp++){let row=[];for(let xi=1;xi<=79;xi++){let v=1;for(let xj=1;xj<=79;xj++)if(xj!==xi)v=gf(v,gf(xp^xj,inv(xi^xj)));row.push(v);ok(v!==0)}parity.push(row);}
 let state=0x1162026;const rnd=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0};
 const enc=data=>data.concat(parity.map(row=>row.reduce((z,v,i)=>z^gf(v,data[i]),0)));
 for(let r=0;r<100;r++){const x=Array.from({length:79},()=>rnd()%256),y=Array.from({length:79},()=>rnd()%256);const ex=enc(x),ey=enc(y);ok(ex.length===85&&ex.slice(0,79).every((v,i)=>v===x[i]));ok(ex.reduce((z,v,i)=>z+(v!==ey[i]),0)>=7);}
 return {run:"R116-FOUR-BIT-RS-LWE-CAPABILITY-20261106",status:"PASS; RESTRICTED credential source only",assertions:a,
 parameters:{q,m,d,ell,max_coin_L1:L,RS_n:85,RS_k:79,RS_distance:7},
 exact_coin_support_log2:log2N,exact_tilt_accept_log2:logAcc,
 four_bit_symbol_failure_log2_upper:logP,whole_256_occurrence_failure_log2_upper:logFail,
 source_nonunique_log2_upper:logUnique,full_public_uniform_LHL_log2_upper:logLHL,
 safe_radius_enumerations:65520,parity_coefficients_tested:474,
 old_ciphertext_bytes:101120,new_ciphertext_bytes:54400,savings_percent:100*73/158,
 limits:"Not QPT hardness; independent 65,814-assertion Python full Berlekamp–Welch decoder is local-only."};
})();
```

## Exact captured execution output

```json
{
  "run": "R116-FOUR-BIT-RS-LWE-CAPABILITY-20261106",
  "status": "PASS; RESTRICTED credential source only",
  "assertions": 66199,
  "parameters": {
    "q": 65521,
    "m": 2000,
    "d": 256,
    "ell": 64,
    "max_coin_L1": 2729,
    "RS_n": 85,
    "RS_k": 79,
    "RS_distance": 7
  },
  "exact_coin_support_log2": 5445.079378072014,
  "exact_tilt_accept_log2": -5.011855021314659,
  "four_bit_symbol_failure_log2_upper": -51.61470115877801,
  "whole_256_occurrence_failure_log2_upper": -153.50946734095174,
  "source_nonunique_log2_upper": -20502.54461733671,
  "full_public_uniform_LHL_log2_upper": -149.18313721740242,
  "safe_radius_enumerations": 65520,
  "parity_coefficients_tested": 474,
  "old_ciphertext_bytes": 101120,
  "new_ciphertext_bytes": 54400,
  "savings_percent": 46.20253164556962,
  "limits": "Not QPT hardness; independent 65,814-assertion Python full Berlekamp–Welch decoder is local-only."
}
```
