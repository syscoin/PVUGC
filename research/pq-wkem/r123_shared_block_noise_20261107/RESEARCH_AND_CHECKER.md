# R123 — Shared-block correlated-noise repair (REJECTED)

**Scope:** One bounded foundational attempt on ORIGINAL-NP source release after R122A; not an optimization. **No secure ORIGINAL-witness advance.** Preserve as a research failure; ordinary progress comment intentionally omitted.
**Continuity:** syscoin/PVUGC PR #1, branch `research/pq-wkem-validation-20260918`, initial head `c959341f376a486d528020886da84c9bb6524f0c` (open/draft/unmerged). Exact predecessor R122A note blob `485e44feca72d07f1c2a4fe1ace04de525b811f3` and latest substantive ordinary comment `6698876958` were read. Offline calculation only.

## Explicit attempted source and correctness
R122A's fixed-FALSE projections concentrated because error vectors were independently sampled across repeated contradictory clause blocks. This attempt replaces independent block errors with ONE error vector shared across all `t` blocks for each capsule pad bit. This removes that concentration but causes an exact public residue leak.

Use ORIGINAL 3CNF `x_t = AND_{j=1}^t [(X_j∨X_j∨X_j) ∧ (¬X_j∨¬X_j∨¬X_j)]`. Each block uses integer
```
A=[[1,1,0,0,0,0,0,0],
   [0,0,1,1,1,0,0,0],
   [0,0,0,0,0,1,1,1],
   [0,3,0,1,2,0,0,0],
   [3,0,0,0,0,0,1,2]],
b=[1,1,1,3,3], z_bad=[0,1,1,0,0,0,-1,2].
```
`A z_bad=b`, `||z_bad||_1=5`. For bit `B_i`, `W=3t`, `E=1`, select `q=12t+5` PRIME and centers `h_0=0`, `h_1=(q-1)/2`. Samples: `t=8,16,32` give `q=101,197,389`. Sample α_{i,j} uniformly over `Z_q^5` conditioned on `Σ_j b^T α_{i,j}=h_{B_i} mod q`. Sample shared `e_i←{-1,0,1}^8` uniformly. Publish `p_{i,j}=A^T α_{i,j}+e_i (mod q)` for every block. For SAT x, every ORIGINAL witness has a one-hot block encoding of total L1 `W`; its projection has noise bounded `EW=3t`, strictly below the nearest-center threshold for q≥4EW+5. All valid witnesses therefore recover the same B_i and precommitted native signature from a public seeded mask. This is correctness for the hypothetical source only, not security.

## Deterministic complete-public FALSE attack
An attacker without any ORIGINAL witness evaluates `V_i=Σ_j ⟨p_{i,j},z_bad⟩ mod q`. As `A z_bad=b`, this equals `h_{B_i}+t c_i mod q`, with `c_i=⟨e_i,z_bad⟩∈[-5,5]`. Since `q=12t+5` and `h_1=6t+2`, for every `t>5`:
- `B_i=0,c_i≥0`: canonical `V_i=t c_i`, thus `V_i mod t=0`;
- `B_i=0,c_i<0`: canonical `V_i=q+t c_i`, thus `V_i mod t=5`;
- `B_i=1`: canonical `V_i=(6+c_i)t+2`, within [0,q), thus `V_i mod t=2`.
Therefore `B_i := [ (V_i mod t)==2 ]` recovers the full bit **on EVERY permitted noise tape**. Repeat for all seed bits, apply the public extractor/KDF, and unmask the native signature. No witness, no oracle and no crypto break. The attack depends only on public p and is classical PPT, hence also a QPT break. Even fully joint checking-key, native VK, context, Aux/J and related capsules cannot restore security because this subset already reveals the bit. This refutes the concrete low-dimensional correlated-error repair, **not** all correlated/noisy LWE sources or WE.

## Execution, exact checker and next obligation
The JavaScript checker below was executed before publication; it exhausts all `3^8=6561` noise vectors for each of `t=8,16,32`, checks exact residue sets and generates 24 genuine full-public `(A^T α + e)` samples per t. A separately executed local Python checker made 59,255 assertions with the same residue sets; a different local enumeration checker made 224 assertions. These tests are algebraic, not PQ hardness experiments. Local full notes and scripts are separate; this published checker is executable as written.

```javascript
function checkR123(){
 const A=[[1,1,0,0,0,0,0,0],[0,0,1,1,1,0,0,0],[0,0,0,0,0,1,1,1],[0,3,0,1,2,0,0,0],[3,0,0,0,0,0,1,2]];
 const b=[1,1,1,3,3],z=[0,1,1,0,0,0,-1,2];
 let checks=0;const ck=(v,m)=>{checks++;if(!v)throw Error(m)};
 const dot=(a,b)=>a.reduce((s,v,j)=>s+v*b[j],0);
 const prime=q=>q>1&&Array.from({length:Math.floor(Math.sqrt(q))-1},(_,i)=>i+2).every(d=>q%d!==0);
 for(let j=0;j<5;j++)ck(dot(A[j],z)===b[j],"false-affine");
 let seed=120300123;
 const rnd=n=>{seed=(1664525*seed+1013904223)>>>0;return seed%n};
 const rows=[];
 for(const t of [8,16,32]){
  const q=12*t+5,h=(q-1)/2;ck(prime(q),"prime");ck(h===6*t+2,"center");
  const sets=[new Set(),new Set()];
  for(let v=0;v<6561;v++){
   let a=v;const e=[];
   for(let j=0;j<8;j++){e.push(a%3-1);a=Math.floor(a/3)}
   const c=dot(e,z);ck(c>=-5&&c<=5,"range");
   for(let bit=0;bit<2;bit++){
    const V=((bit*h+t*c)%q+q)%q, residue=V%t;
    sets[bit].add(residue);
    ck((residue===2)===(bit===1),"public-bit");
   }
  }
  ck([...sets[0]].sort((x,y)=>x-y).join(",")==="0,5","false residues");
  ck([...sets[1]].join(",")==="2","true residues");
  for(let bit=0;bit<2;bit++)for(let n=0;n<12;n++){
   const e=Array.from({length:8},()=>rnd(3)-1);
   const alphas=Array.from({length:t},()=>Array.from({length:5},()=>rnd(q)));
   const original=alphas.reduce((s,alpha)=>s+dot(alpha,b),0);
   alphas[t-1][0]=((alphas[t-1][0]+bit*h-original)%q+q)%q;
   let projection=0;
   for(const alpha of alphas){
    const p=Array.from({length:8},(_,j)=>((e[j]+A.reduce((s,row,k)=>s+row[j]*alpha[k],0))%q+q)%q);
    projection+=dot(p,z);
   }
   const V=(projection%q+q)%q;
   ck((V%t===2)===(bit===1),"full-public");
  }
  rows.push({t,q,noise_vectors:6561,bit0_residues:[...sets[0]].sort((x,y)=>x-y),bit1_residues:[...sets[1]],full_public_samples:24});
 }
 return {run:"R123-SHARED-BLOCK-NOISE-20261107",checks,rows,result:"REJECTED: deterministic extraction on a polynomial fixed-FALSE family; no ORIGINAL WKEM advance"};
}
console.log(JSON.stringify(checkR123(),null,2));
```

Captured executed V8 output:
```json
{
  "run": "R123-SHARED-BLOCK-NOISE-20261107",
  "checks": 59138,
  "rows": [
    {
      "t": 8,
      "q": 101,
      "noise_vectors": 6561,
      "bit0_residues": [
        0,
        5
      ],
      "bit1_residues": [
        2
      ],
      "full_public_samples": 24
    },
    {
      "t": 16,
      "q": 197,
      "noise_vectors": 6561,
      "bit0_residues": [
        0,
        5
      ],
      "bit1_residues": [
        2
      ],
      "full_public_samples": 24
    },
    {
      "t": 32,
      "q": 389,
      "noise_vectors": 6561,
      "bit0_residues": [
        0,
        5
      ],
      "bit1_residues": [
        2
      ],
      "full_public_samples": 24
    }
  ],
  "result": "REJECTED: deterministic extraction on a polynomial fixed-FALSE family; no ORIGINAL WKEM advance"
}
```

**Handoff:** The core missing source remains a classical-PPT `Comp(R_original,x)` that *jointly* generates real ORIGINAL-dependent openings and fully simulatable public LWE checking/capsule/auxiliary correlations. `Open(Comp(R,x),w)` must give the SAME precommitted signature for every ORIGINAL witness, while arbitrary unauthorized QPT recovery/native forgery implies an actual ORIGINAL witness or independent QPT break; the adversary is never required to provide a representation. This repair did not reduce that obligation. Work next on NON-reused, genuinely nonlinear or high-rank statement-dependent mechanisms, including an explicit joint challenge simulation, rather than another constant-dimensional shared-noise tweak. There is no security claim for this direction. Preserve N-of-N honest-erasure, pre-funding availability, SYS/BTC original evidence and hypothetical Bitcoin-native endpoint as separate open obligations. No new assumptions or deployment claims.
