# Anchored Fourier-quotient SOURCE null simulator — restricted construction component (2026-10-27)

**Status:** a proved, source-dependent full-public **false-source** statistical simulator and a classically polynomial all-ORIGINAL-witness release algorithm for a **restricted** kernel NP relation. It is NOT a generic-NP, Bitcoin/Syscoin, hard-true-secure or practical PQ witness-KEM. It is not an ordinary-QPT-LWE proof for structured source matrices.

## Exact source and release distributions

Let q>3 be prime, M in F_q^(r x n), e in F_q^n, and public x bind the relation identity, claim/UTXO, branch, anchors/window, context and intended native checking key. The restricted ORIGINAL relation is: w in {0,1}^n, sum w_i=h, Mw=0, and e^T w=1 (all equations mod q). This is NOT a compiler of arbitrary ORIGINAL NP or Bitcoin block evidence.

Honest setup is classical PPT. Draw a native signing seed K uniformly, derive its actual checking key pk(K), and sample U,Z as independent uniform k-bit strings. Publish D=U XOR Z and V=K XOR U. Encode **one exactly uniform k-bit Z** injectively into ell=ceil(log_m(2^k)) **correlated** base-m digits t_j, m=floor(q/g). For each j independently draw u_j uniform F_q^r and epsilon_j with independent coordinates uniform in {-1,0,1} mod q. Publish

    p_j = M^T u_j + epsilon_j + g*t_j*e   (mod q).

The full public view is (x, pk(K), D, V, p_1..p_ell, context, permissible auxiliary data and related capsules). No source-opening oracle, canonical witness, common intermediate state or setup witness is assumed.

For EVERY accepted ORIGINAL w: w^T p_j = g*t_j + sum_{i:w_i=1} epsilon_ji mod q. If 2h<g and the wrap gap q-(m-1)g>2h, cyclic nearest-codeword decoding recovers every exact t_j, hence the SAME Z and SAME K for every valid w. This is deterministic all-witness correctness, not arbitrary unauthorized-key-recovery extraction.

## New full-column simulator: nonexact anchored Fourier smoothing

For an arbitrary fixed public M,e let P_t be the law of M^T u+epsilon+g*t*e, and let P_0 be the law with t=0. The simulator samples ordinary u,epsilon directly and outputs P_0; it knows no pad digit, key or SOURCE opening.

Let omega=exp(2*pi*i/q), chi_hat(a)=(1+2*cos(2*pi*a/q))/3, and define

    A(M,e)= sum_{z in F_q^n : Mz=0, e^T z != 0}
                 product_i |chi_hat(z_i)|^2.

**Theorem, fixed-statement and arbitrary coherent-QPT distinguishers:** TV(P_t,P_0) <= sqrt(A(M,e)) for every t. For ell independently randomized noisy columns, even if t_j are correlated through one fixed Z, the full joint real-vs-null distance is <= ell*sqrt(A(M,e)), provided allowed auxiliary/related transcripts are conditionally independent of the TARGET u_j and epsilon_j after fixing their shared variables.

**Proof.** For any additive Fourier character z, averaging uniform u annihilates it unless Mz=0. Otherwise the Fourier coefficients of P_t and P_0 differ by factor omega^(g*t*e^T z). Finite Parseval and Cauchy-Schwarz give

    TV(P_t,P_0)
       <= 1/2 sqrt( sum_{Mz=0} |omega^(g*t*e^Tz)-1|^2
                          product_i |chi_hat(z_i)|^2 )
       <= sqrt(A(M,e)).

Critically, the potentially strong Fourier directions satisfying e^Tz=0 CANCEL, even if public ciphertext is nowhere near uniform. Condition on Z,K,U and all allowed shared information and hybrid independently randomized columns one by one; correlations among radix digits cannot increase the sum of these distances. This uses statistical, not conjectured quantum, security. It does not require exact false-source row-shift M^Tc=g e, so it escapes the *method* obstructed by the prior row-span decision theorem, without evading that theorem's logical conclusion.

Under the null joint distribution, conditional on the real K and its REAL pk(K), (U,Z) -> (D=U XOR Z, V=K XOR U) is a bijection; D,V are two exactly uniform independent k-bit strings. Thus no marginal-only pad argument is used. Auxiliary quantum advice may be correlated with public x, K or shared classical variables but MUST be generated without access to target u_j/epsilon_j. Independently randomized related capsules can be conditioned on their common information; secret reuse, unrestricted same-key related release, malicious shared setup and selective opening of target encryption coins are NOT established. A native QPT unforgeability reduction in this false-source null can only handle other capsules simulatable without the native challenge secret. Native signature security does NOT establish the missing hard-true ORIGINAL extraction.

## Independently instantiated sampled-false regime

For uniformly random M in F_q^(r x n), every nonzero z lies in ker M with probability q^(-r). Parseval for ternary noise gives sum_{a in F_q}|chi_hat(a)|^2=q/3. Hence for the stronger full-uniform energy

    S(M)=sum_{0 != z in ker M} product_i |chi_hat(z_i)|^2,
    E_M S(M)=q^(-r)*((q/3)^n - 1).

The bound TV(P_t,uniform F_q^n) <= 1/2 sqrt(S(M)) and Markov imply

    Pr_M[TV(P_t,uniform)>tau] <= E[S]/(4*tau^2),

simultaneously for all t (a shift changes Fourier phase only).

Illustrative, NOT QPT-hardness-certified: q=257, n=440, r=420, e=(1,0,...), h=8, g=18, ternary noise, radix m=14, ell=68 for k=256. All valid witnesses decode exactly because 2h=16<18 and wrap gap 23>16. log2(E[S]) < -537.27, so for tau=2^-150 the chance a sampled M fails uniform simulation is <2^-239.27; 68 columns give distance <2^-143.91 on a good M. A random M has an anchored binary h=8 witness with probability at most binom(439,7)*257^-420 <2^-3313. Thus this is an independently substantiated **sampled false distribution**, NOT security for all false ORIGINAL x. Matrix and ciphertext storage at two bytes per field element is 369,600 and 59,840 bytes respectively, excluding native keys and context. No hard-true parameter/security estimate follows. A planted true M is not distributed as random false M.

## Exact non-rowshift finite test and reproducibility

Over F_31 with 22 columns, binary h=2 and g=5, the checker constructs a 20-row FALSE M with kernel generated by short v anchored e^Tv=0 and dense z anchored e^Tz=22. Exhaustive weight-2 ORIGINAL checking finds no accepted w; exact false row-shift is impossible because e^Tz!=0. Integer convolution of all 3^22 ternary-noise combinations on the 2D quotient gives max_t TV(P_t,P_0)=37136/3486784401 = 1.065050078500681e-5. The anchored Fourier bound is 3.334819508588951e-5. However TV(P_0, full uniform)=0.8387096774193549 due to the short unanchored v. A separate true M has TWO distinct valid ORIGINAL binary witnesses and the checker verifies 600 same-digit releases. Exact three-bit (D,V) correlations are exhausted for every native seed K. Tests ran twice and outputs matched; exact convolution and simple numerical Fourier/Markov computations are NOT cryptographic QPT experiments.

## What is still missing

The decisive unresolved equations must hold TOGETHER for a single classical PPT generic-NP compiler x -> (M_x,e_x) rather than for separately sampled random false and planted true matrices:

    ALL valid ORIGINAL W: f_x(W) binary, fixed weight h, M_x f_x(W)=0,
         e_x^T f_x(W)=1, Dec(x,C,W)=precommitted K;
    ALL false x: A(M_x,e_x) <= negligible(lambda)^2 / ell^2
         OR an independently justified full-joint QPT simulator;
    ANY coherent QPT adversary recovering K or forging intended native path on
         hard-true x -> ORIGINAL W OR independent PQ break,
         without the adversary volunteering any representation.

This work provides the proved fixed-M noise simulator and its random-false instantiation only. Arbitrary hard-true key-recovery extraction, generic ORIGINAL compilation, quantum PoW bounds, malicious N-of-N ceremony/abort/graph composition, DA, multiple-capsule/selective-opening and the conditional native Bitcoin PQ endpoint remain unresolved. It does NOT solve the user's stopping condition.

## Published exact self-contained checker and captured output

The following JavaScript function was **executed in the research run**, twice with byte-identical JSON results. It is self-contained and executable in a standard JavaScript runtime.

```javascript
const checkFourier = function checkFourier(){
 const q=31,n=22,g=5,h=2,m=Math.floor(q/g), z=[1,15,21,1,0,0,2,15,22,2,23,8,23,15,27,6,1,25,9,2,23,21];
 const e=Array(n).fill(0),v=Array(n).fill(0);e[0]=e[2]=1;v[4]=v[5]=1;
 let tests=0;const ok=(v,msg)=>{if(!v)throw Error(msg||"check failed");tests++;},mod=x=>(x%q+q)%q;
 const dot=(a,b)=>mod(a.reduce((s,x,i)=>s+x*b[i],0));
 function rowsOrthogonalTo(basis){
  const A=basis.map(b=>b.map(mod)),piv=[];let p=0;
  for(let c=0;c<n&&p<A.length;c++){
   let j=p;while(j<A.length&&!A[j][c])j++;if(j==A.length)continue;
   [A[p],A[j]]=[A[j],A[p]];let inv=1;while(mod(inv*A[p][c])!==1)inv++;
   A[p]=A[p].map(x=>mod(x*inv));
   for(let k=0;k<A.length;k++)if(k!=p&&A[k][c]){const t=A[k][c];A[k]=A[k].map((x,i)=>mod(x-t*A[p][i]));}
   piv.push(c);p++;
  }
  ok(p===basis.length,"bad basis rank");
  const out=[];
  for(let f=0;f<n;f++)if(!piv.includes(f)){
   const row=Array(n).fill(0);row[f]=1;
   for(let j=0;j<piv.length;j++)row[piv[j]]=mod(-A[j][f]);
   for(const b of basis)ok(dot(row,b)===0,"row not orthogonal");
   out.push(row);
  }
  return out;
 }
 const M=rowsOrthogonalTo([v,z]);ok(M.length===20);
 ok(dot(e,v)===0&&dot(e,z)===22,"anchor");
 for(let i=0;i<n;i++)for(let j=i+1;j<n;j++){
  const w=Array(n).fill(0);w[i]=w[j]=1;
  if(dot(e,w)===1)ok(M.some(row=>dot(row,w)!==0),"false source admits w");
 }
 let counts=new Float64Array(q*q);counts[0]=1;
 for(let i=0;i<n;i++){
  const next=new Float64Array(q*q);
  for(let a=0;a<q;a++)for(let b=0;b<q;b++){const c=counts[a*q+b];if(!c)continue;
   for(let s=-1;s<=1;s++)next[mod(a+s*v[i])*q+mod(b+s*z[i])]+=c;
  }
  counts=next;
 }
 const total=3**n;ok(counts.reduce((a,b)=>a+b,0)===total,"mass");
 let maxTV=0;
 for(let t=0;t<m;t++){
  const shift=mod(g*t*dot(e,z));let L1=0;
  for(let a=0;a<q;a++)for(let b=0;b<q;b++)L1+=Math.abs(counts[a*q+b]-counts[a*q+mod(b-shift)]);
  maxTV=Math.max(maxTV,L1/(2*total));
 }
 let L1=0;for(const c of counts)L1+=Math.abs(q*q*c-total);
 const uniformTV=L1/(2*q*q*total);
 let anchor=0,full=0;
 for(let a=0;a<q;a++)for(let b=0;b<q;b++){
  if(a===0&&b===0)continue;
  let prod=1;
  for(let i=0;i<n;i++){const k=mod(a*v[i]+b*z[i]), c=(1+2*Math.cos(2*Math.PI*k/q))/3;prod*=c*c;}
  full+=prod;if(mod(b*dot(e,z))!==0)anchor+=prod;
 }
 ok(maxTV<=Math.sqrt(anchor)+1e-10,"Parseval");
 ok(uniformTV>0.8 && anchor<full,"strict anchored advantage");
 const w1=Array(n).fill(0),w2=Array(n).fill(0);w1[0]=w1[1]=1;w2[2]=w2[3]=1;
 const T=rowsOrthogonalTo([w1,w2]);ok(T.length===20);
 let valid=[];
 for(let i=0;i<n;i++)for(let j=i+1;j<n;j++){
  const w=Array(n).fill(0);w[i]=w[j]=1;
  if(dot(e,w)===1&&T.every(row=>dot(row,w)===0))valid.push([i,j]);
 }
 ok(JSON.stringify(valid)===JSON.stringify([[0,1],[2,3]]),"true witnesses");
 let state=0x1234567;const rnd=k=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state%k;};
 for(let k=0;k<300;k++){
  const digit=rnd(m), u=T.map(()=>rnd(q)),noise=Array.from({length:n},()=>rnd(3)-1);
  const p=Array.from({length:n},(_,i)=>mod(g*digit*e[i]+noise[i]+T.reduce((a,row,j)=>a+row[i]*u[j],0)));
  for(const w of [w1,w2]){
   const val=dot(w,p);
   const options=Array.from({length:m},(_,j)=>({j,dist:Math.min(mod(val-g*j),mod(g*j-val))})).sort((a,b)=>a.dist-b.dist);
   ok(options[0].j===digit,"honest same key digit");
  }
 }
 for(let K=0;K<8;K++){
  const seen=new Set();
  for(let U=0;U<8;U++)for(let Z=0;Z<8;Z++){seen.add(((U^Z)*8)+(K^U));}
  ok(seen.size===64,"fixed native K pair not uniform");
 }
 const qBig=257,nBig=440,rBig=420,hBig=8,gBig=18,mBig=Math.floor(qBig/gBig),ell=Math.ceil(256/Math.log2(mBig));
 const logExpected=(nBig-rBig)*Math.log2(qBig)-nBig*Math.log2(3);
 const logBad=logExpected+298,logJoint=Math.log2(ell)-150;
 ok(ell===68&&2*hBig<gBig&&qBig-(mBig-1)*gBig>2*hBig);
 ok(logExpected< -537&&logBad< -239&&logJoint< -143);
 return {record:"anchored_fourier_null_20261027",status:"restricted statistical simulator; NOT generic-NP WKEM",q,n,source_rows:M.length,valid_false_witnesses:0,valid_true_witnesses:2,finite_full_public_shift_tv:maxTV,finite_full_uniform_tv:uniformTV,anchored_energy:anchor,full_energy:full,anchored_tv_bound:Math.sqrt(anchor),correct_digit_decodings:600,native_share_pair_per_K:64,large_example:{q:qBig,n:nBig,r:rBig,h:hBig,g:gBig,radix:mBig,columns:ell,log2_expected_full_energy_upper:logExpected,log2_sampled_bad_probability_upper:logBad,log2_good_M_joint_distance_upper:logJoint},assertions:tests};
};
console.log(JSON.stringify(checkFourier(),null,2));
```

Captured output:

```json
{
  "record": "anchored_fourier_null_20261027",
  "status": "restricted statistical simulator; NOT generic-NP WKEM",
  "q": 31,
  "n": 22,
  "source_rows": 20,
  "valid_false_witnesses": 0,
  "valid_true_witnesses": 2,
  "finite_full_public_shift_tv": 0.00001065050078500681,
  "finite_full_uniform_tv": 0.8387096774193549,
  "anchored_energy": 1.112102115486545e-9,
  "full_energy": 6.271604939383705,
  "anchored_tv_bound": 0.00003334819508588951,
  "correct_digit_decodings": 600,
  "native_share_pair_per_K": 64,
  "large_example": {
    "q": 257,
    "n": 440,
    "r": 420,
    "h": 8,
    "g": 18,
    "radix": 14,
    "columns": 68,
    "log2_expected_full_energy_upper": -537.271009333431,
    "log2_sampled_bad_probability_upper": -239.27100933343104,
    "log2_good_M_joint_distance_upper": -143.91253715874967
  },
  "assertions": 739
}
```

## Provenance

Run label: anchored-fourier-null-20261027-turn11; scheduler execution UUID not supplied. Repo syscoin/PVUGC PR #1, existing research branch research/pq-wkem-validation-20260918, starting SHA 94f75c08bc8c3e9c6010a4eab63739190e864f21; latest substantive ordinary comment examined 6453918351; exact-version parent proof research/pq-wkem/rowshift_decision_bound_20261027/PROOF.md, blob 298fcc459b9afc3d102fd0aa7a6eb4c95e72f5de. Actions: get_pr_info, fetch_issue_comments, fetch_file, local Python finite checker, pure JavaScript finite checker, create_file if successful, subsequent readbacks. Offline research only; no external web, literature or unrelated repository access. Local Python checker ran twice with 1060 assertions per run and identical outputs, matching exact quotient-TV values; published JavaScript checker ran twice with 739 checks per run, identical results. No subagents or independent external reviews invoked. Prior exact-base-tree creation attempt returned GitHub 422 Invalid tree info; it did not update any branch. Publication uses single-file Contents API instead.
