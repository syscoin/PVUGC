# Packed-pair distributed LWE SOURCE — research-only proof and executed checker
**Date:** 2026-10-29. **Source:** syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, exact starting SHA d9335e6cc8c9581988c5a8da815b33da62184aca. Selected predecessor: distributed_prime_lwe_source_20261029/RESEARCH.md, blob 5339c8fdde647c2f217593f57e0444730a4a3bf5, and ordinary comment 6503826098. The PR was open, draft, unmerged on read. This record is offline research; no external literature, unrelated repo, entire PR diff, independent agent or deployment.

## Result and limitation
**Positive restricted efficiency result; not a practical generic-NP witness-KEM.** The previous distributed prime-modulus LWE SOURCE encrypted each native-secret bit separately. A four-center, two-bit-per-ciphertext release with high-entropy bounded-weight binary coins now encrypts two adjacent native-secret bits in one ciphertext. This halves the aggregate and contributor ciphertext counts, preserves deterministic every-SOURCE-witness SAME-capability correctness on every accepted coin sample, and uses *the identical LWE distribution and QPT assumptions* as the predecessor. Its joint statistical security bound becomes strictly smaller despite the weight restriction. The ORIGINAL-NP recovery/extraction obligation remains completely unsolved.

## Exact distributions, assumptions and algorithms
Let q be an odd prime; n,m,N,J and lambda polynomially bounded; chi a classical efficiently samplable error distribution with support [-B,B]. Choose 0<=w<=m with g=floor(q/4)>2NwB and T={r in {0,1}^m: wt(r)<=w}, S=sum_{k=0}^w C(m,k). Generate uniformly A in Z_q^(n x m), s in Z_q^n, e from chi^m, and b=A^T s+e modulo q; publish H=[A;b^T]. Any pair (s',e') with b=A^T s'+e' and ||e'||_infinity<=B is a valid SOURCE witness. Setup is classical PPT and does not use ORIGINAL NP.

Use actual native KeyGen to generate (sk_N,pk_N), canonically serialize the complete usable native secret to bits and pair adjacent bits into digits a_l=bit_(2l)+2bit_(2l+1) in {0,1,2,3}; if needed, pad the final high bit and bind the original length. For every digit, N-1 contributors receive independent uniform q-ary z_i, and the final contributor receives z_N=a_l-sum_(i<N) z_i modulo q. A fixed corruption set of at most N-1 contributors may have every share and every encryption coin disclosed adaptively after publication. Honest dealer, pre-funding validation, private authenticated channels and protected contributor secrecy/erasure are ASSUMPTIONS; malicious dealer and fully keyless N-of-N KeyGen are not solved. A separate keyless assembler only receives publicly authenticated contributor ciphertexts.

For each capsule j, contributor i, digit l choose independent r_{j,i,l} uniform on T and publish
    u_{j,i,l} = A r_{j,i,l} mod q,
    v_{j,i,l} = b^T r_{j,i,l} + g z_{i,l} mod q.
The assembler sums u and v across i. Every alias capsule uses independent r but the same sk_N and its shares ONLY inside one claim/UTXO/branch/intended-pk/challenge/anchors/window authorization scope. Another scope MUST have a distinct native key. Contribution authenticators are independent keys, and any auxiliary data must be simulatable without the protected secret and SOURCE witness.

Sample r by uniform m-bit rejection until wt(r)<=w, with at most 4lambda attempts. Conditioned on success r is exactly uniform T; if w>=floor(m/2), the acceptance rate is at least 1/2, so pre-funding abort probability <=2^(-4lambda), independent of native secrets. This makes the algorithms strict classical PPT with negligible independent abort and no irreversible-funding step before success.

For ANY valid SOURCE witness (s',e'), public off-chain release computes the full aggregated ciphertext residual
    d=v-s'^T u = g a_l + e'^T sum_i r_i mod q.
Its integer noise has absolute value <=NwB. The circular distances between centers 0,g,2g,3g modulo q have minimum g, so g>2NwB guarantees unique nearest-center decoding for every valid witness and every accepted r, including distinct witness states. Reassemble the identical precommitted sk_N and verify its true pk_N before signing the intended challenge off chain with the ordinary native signature scheme. Bitcoin is not asked to verify original NP, traces, proofs or adaptor algebra.

## Full-public QPT hybrid (restricted distribution only)
Assume independently nonuniform QPT decisional LWE for exactly (q,n,m,chi) with classical honest sampling, and independently QPT native EUF-CMA for a genuine pk_N with classical signing queries. No practical 128-bit calibration or native SLH implementation is claimed. The full public view includes relation/source H and statement/context/UTXO/branch/anchors, genuine pk_N, every individual and aggregate ciphertext, independent contribution authenticators and simulatable auxiliary data, J same-key same-scope related capsules, and all adaptively disclosed shares and complete coins of the fixed-at-start corrupted cohort. Quantum adversaries may process all classical transcripts jointly/coherently; quantum-superposition signing/opening is not an allowed interface. There is no extra hidden share/source-witness-correlated QPT advice, malicious dealer proof, independently claimed sharing-to-pk NIZK, or other-scope same-key reuse.

For uniform H in Z_q^((n+1) x m), the family r->Hr over r uniform T has exact collision probability q^(-(n+1)) for any distinct r,r': the binary difference has a +/-1 unit coordinate modulo prime q. Its exact second moment and Cauchy-Schwarz yield
    delta_T = 1/2 sqrt((q^(n+1)-1)/S)
as an upper bound on average *complete (u,v)* distance to uniform, jointly with H. Translation of the last coordinate by g z shifts distributions without changing delta_T, so replacing a protected contributor's encrypted z by encryption of zero costs at most 2delta_T. Condition on pk_N, all nonprotected shares/coins and all independent public context: the protected z may depend on the actual native sk_N and other shares, but is independent of H. Independent r across J*L protected ciphertexts supports a joint product hybrid costing at most 2JLdelta_T; related same-key correlations remain intact.

Use two straight-line ordinary QPT-LWE source replacements (real H -> uniform H -> real H) around the protected-to-zero ciphertext hybrid, then embed the genuine native EUF-CMA challenger pk_N. The simulator does NOT know sk_N, SOURCE witness or protected share. It chooses all other q-ary shares uniformly, honestly encrypts them and opens any fixed predeclared corrupt participants' shares and coins as asked; it publicly encrypts zero for protected contributions. The source/capsule/challenge/checking-key correlations are generated together. A recovered complete usable K permits a native signature on a fresh intended target challenge; an accepted fresh native signature itself breaks native EUF-CMA. Hence under honest TRUE-LWE H:
    Pr[unauthorized native-key recovery or accepted fresh native forgery]
      <= 2 Adv_QPT-DecLWE + 2 J L delta_T + Adv_QPT-native-EUF-CMA.
No SourceOpen oracle, rewinding, random-oracle extraction or adversary-supplied intermediate representation is assumed.

## Why efficiency does not weaken this restricted bound
For w>=floor(m/2) and w<m, S>=2^(m-1), so delta_T<=sqrt(2)*delta_old where delta_old uses 2^m uniform binary coins. For even old bit length L_old and L_new=L_old/2, the complete-joint statistical error term 2J L_new delta_T is <(1/sqrt(2)) times the OLD bound 2J L_old delta_old. The ordinary QPT LWE assumption uses the **same q,n,m,chi** and native EUF-CMA uses the **same pk generation**, not a weaker replacement assumption. With odd-length keys, explicitly use ceil(L_old/2). This is an algebraic statistical bound, not a resource benchmark or proof of underlying QPT hardness.

Illustrative prime q=16,777,213, n=256,m=6800,B=128,N=4,J=2,w=4095: g=4,194,303, max error NwB=2,096,640, nearest-center half spacing=2,097,151.5, a narrow but *deterministic* 511.5 margin. Exact integer binomial computation in extended offline checker puts rejection probability at 2^(-212.116103), and joint statistical term approximately 2^(-308.000033) versus predecessor's 2^(-307.000033). Bit-packed 24-bit field serialization: H remains 5,242,800 bytes; 256-bit illustrative key's aggregate capsule drops 197,376 -> 98,688 bytes and N individual ciphertexts 789,504 -> 394,752 bytes per capsule. Naive dominant field additions also approximately halve, but no timing benchmark was executed. No real SLH parameters or security claims follow from this illustration.

## Boundaries, failed alternatives and next equation
This is still an **honestly TRUE-LWE preimage SOURCE**, not arbitrary ORIGINAL NP. On adversarial fixed-FALSE SOURCE data (including the prior degenerate A=0 example), native-key bits may be public. No ORIGINAL-to-SOURCE compiler maps every valid ORIGINAL witness to one common precommitted capability while protecting every fixed FALSE ORIGINAL statement. The missing construction is an independently justified witness-free classical-PPT Comp(R_original,x,claim,context,pk) together with Open(R_original,x,W) and the corresponding joint challenge simulator, satisfying:
    for all valid ORIGINAL W: Release(Comp(...),Open(W))=one precommitted K;
    for every FALSE x: full-public QPT hiding of K;
    for arbitrary unauthorized hard-TRUE native-key recovery/forgery:
        efficiently obtain actual ORIGINAL W OR independently justified QPT break.
It cannot assume an attacker supplies a SOURCE representation or SourceOpen. None of these equations is established here. Separate malicious N-of-N preauthorization, graph/abort/erasure, pre-funding data availability, actual SYS/BTC parent headers/AuxPoW/coinbase-tag/ancestor-window authentication, and a hypothetical no-EC native-PQ Bitcoin endpoint remain unresolved. Never infer deployment or stop the research task from this result.

## Exact checker, execution and provenance
The embedded self-contained Node checker below was run **twice identically** before publication. It explicitly generates full individual/aggregate ciphertexts, corrupt share/coin openings and two separate 256-bit same-key capsules with two distinct valid SOURCE witnesses; exhaustively enumerates 59,049 small matrices for the complete-ciphertext leftover and translation bound and exact collision frequency; tests q-ary N-1 share distributions; verifies the deterministic margin and same-security inequality at the illustration. It does not test real native signatures, generic NP, or QPT hardness. The extended local-only Python checker passed **4,510 assertions twice** with byte-identical captured output and independently counted exact 6,800-bit combinatorial support. Initial local development errors were corrected before final successful runs. All research is offline.

### Exact executed standalone Node checker
Save the following JavaScript fenced block as check.js; execute with Node. The following JSON block is its exact captured deterministic output.

```javascript
// Offline exact checker, executable with Node; no dependencies.
console.log(JSON.stringify((function runChecker(){
  let assertions=0,seed=20261029>>>0;
  const ok=(x,m)=>{assertions++;if(!x)throw Error(m);};
  const rnd=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;};
  const ri=n=>rnd()%n,mod=(x,q)=>(x%q+q)%q;
  const q=1009,n=2,m=17,B=1,N=4,J=2,w=11,g=Math.floor(q/4);
  ok(g>2*N*w*B,"packing margin");
  let A0=Array.from({length:m},()=>ri(q)),A=[A0,A0.map(x=>mod(3*x,q))];
  let s=[ri(q),ri(q)],s2=[mod(s[0]-3,q),mod(s[1]+1,q)];
  let e=Array.from({length:m},()=>ri(3)-1);
  let b=Array.from({length:m},(_,j)=>mod(A[0][j]*s[0]+A[1][j]*s[1]+e[j],q));
  for(let j=0;j<m;j++)ok(mod(b[j]-A[0][j]*s2[0]-A[1][j]*s2[1],q)===mod(e[j],q),"second witness");
  let K=Array.from({length:32},()=>ri(256)),digits=[];
  for(let byte of K)for(let k=0;k<8;k+=2)digits.push(((byte>>k)&1)+2*((byte>>(k+1))&1));
  ok(digits.length===128,"packing");
  let draws=0,maxerr=0;
  const dist=(x,y,p)=>Math.min(mod(x-y,p),mod(y-x,p));
  const coin=()=>{for(let i=0;i<1024;i++){draws++;let r=Array.from({length:m},()=>ri(2));if(r.reduce((a,b)=>a+b,0)<=w)return r;}throw Error("sampler abort");};
  for(let j=0;j<J;j++){
    let recoveredDigits=[];
    for(let a of digits){
      let zs=Array.from({length:N-1},()=>ri(q));zs.push(mod(a-zs.reduce((x,y)=>x+y,0),q));
      let Cs=zs.map(z=>{
        let r=coin(),u=A.map(row=>mod(row.reduce((t,x,k)=>t+x*r[k],0),q));
        let v=mod(b.reduce((t,x,k)=>t+x*r[k],0)+g*z,q);
        ok(mod(v-b.reduce((t,x,k)=>t+x*r[k],0)-g*z,q)===0,"contributor encryption");
        return {r,u,v,z};
      });
      let u=[0,0],v=0;
      for(let C of Cs){u=u.map((x,i)=>mod(x+C.u[i],q));v=mod(v+C.v,q);}
      let rsum=Array.from({length:m},(_,k)=>Cs.reduce((z,C)=>z+C.r[k],0));
      let noise=e.reduce((z,x,k)=>z+x*rsum[k],0);
      maxerr=Math.max(maxerr,Math.abs(noise));
      ok(Math.abs(noise)<=N*w*B,"max noise");
      for(let witness of [s,s2]){
        let residual=mod(v-u.reduce((z,x,i)=>z+x*witness[i],0),q);
        ok(residual===mod(g*a+noise,q),"full release identity");
        let nearest=0;
        for(let d=1;d<4;d++)if(dist(residual,g*d,q)<dist(residual,g*nearest,q))nearest=d;
        ok(nearest===a,"same digit for two SOURCE witnesses");
      }
      let residual=mod(v-s[0]*u[0]-s[1]*u[1],q),nearest=0;
      for(let d=1;d<4;d++)if(dist(residual,g*d,q)<dist(residual,g*nearest,q))nearest=d;
      recoveredDigits.push(nearest);
      for(let C of Cs.slice(0,N-1))ok(C.v===mod(b.reduce((z,t,k)=>z+t*C.r[k],0)+g*C.z,q),"fixed N-1 coin opening");
    }
    let recovered=Array.from({length:32},(_,i)=>recoveredDigits[4*i]|recoveredDigits[4*i+1]<<2|recoveredDigits[4*i+2]<<4|recoveredDigits[4*i+3]<<6);
    for(let i=0;i<32;i++)ok(recovered[i]===K[i],"entire 256bit capability");
  }
  const q0=3,m0=5,T=[];
  for(let z=0;z<32;z++){let r=Array.from({length:m0},(_,i)=>(z>>i)&1);if(r.reduce((a,b)=>a+b,0)<=3)T.push(r);}
  ok(T.length===26,"bounded-weight support");
  let tv=0,tvshift=0,collide=0;
  for(let h=0;h<59049;h++){
    let x=h,H=[[],[]];for(let i=0;i<2;i++)for(let k=0;k<m0;k++){H[i].push(x%3);x=Math.floor(x/3);}
    const hash=r=>H.map(row=>mod(row.reduce((z,t,k)=>z+t*r[k],0),3));
    let ct=Array(9).fill(0);
    for(let r of T){let v=hash(r);ct[3*v[0]+v[1]]++;}
    for(let i=0;i<9;i++){tv+=Math.abs(ct[i]/26-1/9)/2;tvshift+=Math.abs(ct[i]-ct[3*Math.floor(i/3)+mod(i%3-1,3)])/52;}
    let a=hash(T[1]),b=hash(T[17]);if(a[0]===b[0]&&a[1]===b[1])collide++;
  }
  ok(collide===59049/9,"exact pairwise-universal collision");
  tv/=59049;tvshift/=59049;
  const delta=.5*Math.sqrt(8/26);
  ok(tv<=delta+1e-9&&tvshift<=2*delta+1e-9,"complete-ciphertext leftover bound");
  for(let a=0;a<4;a++){
    for(let index=0;index<3;index++){
      let pairs=new Set;
      for(let x=0;x<5;x++)for(let y=0;y<5;y++){
        let z=mod(a-x-y,5),v=[x,y,z];
        pairs.add(v.filter((_,i)=>i!==index).join(","));
        ok(mod(x+y+z,5)===a,"additive share correctness");
      }
      ok(pairs.size===25,"all fixed N-1 shares uniform for any digit");
    }
  }
  const Q=16777213,NN=4,WW=4095,BB=128,Lold=256,Lnew=128;
  ok(Math.floor(Q/4)>2*NN*WW*BB,"large deterministic margin");
  let prime=true;for(let p=2;p*p<=Q;p++)if(Q%p===0)prime=false;
  ok(prime,"illustrative modulus prime");
  ok(Lold===2*Lnew&&Lnew*Math.SQRT2<Lold,"improved statistical upper bound from majority coin support");
  const oldlog=Math.log2(2*2*Lold)-1+((256+1)*Math.log2(Q)-6800)/2;
  const newBound=oldlog-.5;
  ok(newBound<-128,"statistical term below target");
  return {status:"PASS",assertions,seed:20261029,toy:{q,n,m,B,N,J,weight_cap:w,key_bits:256,digits_per_capsule:128,coin_draw_attempts:draws,max_observed_noise:maxerr,max_allowed_noise:N*w*B},exhaustive_small:{q:q0,m:m0,coin_support:26,H_matrices:59049,mean_tv:+tv.toFixed(9),mean_shift_tv:+tvshift.toFixed(9),second_moment_bound:+delta.toFixed(9)},large:{q:Q,n:256,m:6800,N:NN,B:BB,J:2,weight_cap:WW,worst_case_noise:NN*WW*BB,half_center_spacing:Math.floor(Q/4)/2,aggregate_old_bytes:197376,aggregate_new_bytes:98688,old_log2_statistical_bound:+oldlog.toFixed(6),new_log2_conservative_upper_bound:+newBound.toFixed(6)},limitation:"Only honest TRUE-LWE SOURCE; no arbitrary ORIGINAL-NP compiler, arbitrary fixed-FALSE theorem, malicious setup, QPT-hardness calibration, or native SLH implementation."};
})(),null,2));
```

### Captured checker output

```json
{
  "status": "PASS",
  "assertions": 3474,
  "seed": 20261029,
  "toy": {
    "q": 1009,
    "n": 2,
    "m": 17,
    "B": 1,
    "N": 4,
    "J": 2,
    "weight_cap": 11,
    "key_bits": 256,
    "digits_per_capsule": 128,
    "coin_draw_attempts": 1098,
    "max_observed_noise": 11,
    "max_allowed_noise": 44
  },
  "exhaustive_small": {
    "q": 3,
    "m": 5,
    "coin_support": 26,
    "H_matrices": 59049,
    "mean_tv": 0.210193099,
    "mean_shift_tv": 0.302013842,
    "second_moment_bound": 0.277350098
  },
  "large": {
    "q": 16777213,
    "n": 256,
    "m": 6800,
    "N": 4,
    "B": 128,
    "J": 2,
    "weight_cap": 4095,
    "worst_case_noise": 2096640,
    "half_center_spacing": 2097151.5,
    "aggregate_old_bytes": 197376,
    "aggregate_new_bytes": 98688,
    "old_log2_statistical_bound": -307.000033,
    "new_log2_conservative_upper_bound": -307.500033
  },
  "limitation": "Only honest TRUE-LWE SOURCE; no arbitrary ORIGINAL-NP compiler, arbitrary fixed-FALSE theorem, malicious setup, QPT-hardness calibration, or native SLH implementation."
}
```
