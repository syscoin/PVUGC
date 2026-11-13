# R161 — One-hot integral-norm source for ORIGINAL 3CNF: rejected projective release

**Result: no positive generic WKEM advance.** One original-relation compiler candidate was constructed and tested against its entire intended source distribution. This note preserves the exact release equation, an integer-representation-to-ORIGINAL-witness extraction lemma, and a universal FALSE-source bypass showing why that lemma alone does not secure the release. It is not a PQ-KEM, an LWE hardness proof, an optimization, or a reason to notify the user.

**Continuity:** syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, starting head 3b2d011d3fb8104f21ff2d6f25c7d427f2c33bae, open/draft/unmerged; preceding R160 research file blob 16ece438521b9399a846201eddd81e6f888d5001, last substantive ordinary comment 6718361572 (R153). The R160 syntactic gate-multiple column was known to be source-rowspace redundant and publicly exposed its constant coefficient. R161 instead asks if genuinely integer-only low-norm constraints can create a witness extraction barrier without the R138-style rational bypass.

## Exact polynomial-time ORIGINAL-3CNF representation

Let φ be any original 3CNF with n variables, m clauses of 3 literal occurrences (repetitions allowed). Work over integer coefficients first, then mod prime q. For each variable i create a block (v_i,0,v_i,1) with normalization v_i,0+v_i,1=1. For each clause j create seven coordinates c_j,s, one for each satisfying local literal assignment s∈{0,1}^3\{000}, and require Σ_s c_j,s=1. For each occurrence k of variable i with polarity positive or negative, require Σ_{s:s_k=1} c_j,s equal to v_i,1 or v_i,0 respectively. Collect these equations as A_φ z=b_φ. The number of columns is 2n+7m; the number of equations is n+4m. The construction is deterministic classical PPT.

Given any satisfying ORIGINAL Boolean witness w, set its variable block to the appropriate unit vector and the j-th clause block to the unit vector at the three literal truth values induced by w. This representation z_w satisfies A_φ z_w=b_φ, is integral, and has ||z_w||_1=||z_w||_2²=n+m=B. All valid ORIGINAL witnesses use different allowed blocks but can cancel the same linear phase.

**Proved supplied-INTEGER-representation lemma:** If an integer z solves A_φ z=b_φ and ||z||_2²≤B, then every normalized variable and clause block has squared norm at least one, so each must have squared norm exactly one. An integer block with coordinates summing to one and squared norm one is a positive unit vector. The occurrence equalities then imply the selected local clause choices agree with a Boolean assignment, and each is one of the seven satisfying assignments. Thus the variable entries extract an ORIGINAL satisfying witness. For equations interpreted modulo q, sufficient no-wrap parameter restrictions are additionally necessary; the statement as proved here is over integers.

## Candidate LWE-like release — complete equations, not a standard-LWE instantiation

Setup samples r uniform from F_q^(n+4m), e∈[-E,E]^(2n+7m), e0∈[-E0,E0), and a fixed capability bit k. Publish A_φ,b_φ and C=A_φ^T r+e mod q, t=b_φ^T r+Δk+e0 mod q; for a full protocol x would also include the relation identity, UTXO/claim, branch, anchors/window, intended native VK and path. For each valid Boolean witness, classical Open computes centered(t-z_w^T C) and decodes k. It equals Δk+e0-z_w^T e mod q, with |error|≤E0+EB. This is all-valid SAME-capability correctness in the stated noise/no-wrap regime, not cryptographic soundness.

It would be invalid to call (A_φ,C,t) standard scalar decisional LWE: A_φ is statement-derived and highly structured, and the t correlation includes b_φ. No genuine ordinary-LWE joint challenge simulator, checking key, auxiliary-data simulator or related-capsule simulator is instantiated here.

## Fatal universal fractional projective opening

For *every* formula φ, including false formulas, the following vector is publicly computable. Set every variable block to (1/2,1/2). In every clause block put probability 1/4 on satisfying literal patterns 100,010,001,111 and zero on the other three patterns. Each of the three literal marginals equals 1/2 regardless of variable polarity, so this rational z* satisfies A_φ z*=b_φ. Its ||z*||_1=B (same as a valid witness), while ||z*||_2²=n/2+m/4 < B for nonempty instances. With integer y=4z*, the public attacker has A_φ y=4b_φ, ||y||_1=4B and ||y||_2²=8n+4m.

Given actual public source bytes (C,t), *without any witness or decryption key*, compute centered(4t−y^T C) mod q. This equals 4Δk+4e0−y^T e, with error magnitude at most 4(E0+EB) on **every** bounded-noise tape, not just with high probability. Whenever 4Δ is well separated from zero by this bound and q is large enough to avoid wraparound, nearest-neighbor decoding recovers k from this PUBLIC expression. The attack does not submit y to Open, bypassing an integer-only representation check; it simply evaluates the same public linear phase at scale four. Thus the honest integral low-norm extraction lemma provides no reduction from arbitrary capability recovery to ORIGINAL witness.

The exact fixed FALSE example φ=(x∨x∨x) ∧ (¬x∨¬x∨¬x) has n=1,m=2,B=3, nine source rows, sixteen columns. Choose q=769, Δ=64, E0=E=1. The attack's residual is 256k plus bounded error of magnitude ≤16, so decoding is unambiguous for both bit values and every allowed noise realization. Its normalized ℓ1 is 3 and normalized squared ℓ2 is 1 versus the legitimate Boolean squared norm 3.

## Security and generalization boundary

The mathematically useful fact is only “small integer solution ⇒ ORIGINAL witness.” This is **not** “arbitrary successful capability recovery ⇒ ORIGINAL witness”; the explicit FALSE attack proves the latter cannot hold for this source. Rational vectors and their integer projective scales are legal adversarial computations even if the honest Open rejects them. This adds a separate integer-shortest-vector repair to the already recorded R138 fractional-source failures, and is not a major new impossibility result beyond that family.

A complete full-public experiment would need (R_ORIGINAL,x), capsule, checking key J/CK, Aux, native VK, claim/UTXO, anchors/window, branch, context, related capsules, permitted classical selective openings and adversarial quantum advice; each must be jointly simulated in a real ordinary-QPT-LWE hybrid. Neither that simulator nor FALSE hiding nor hard-TRUE arbitrary recovery extraction exists for R161. Honest algorithms here are classical PPT; nothing in this note turns them into a QPT-secure source, malicious-secure N-of-N setup, Bitcoin-native endpoint or deployment claim. Ordinary PQ LWE is not broken. Do not optimize packing of this rejected source or promote this supplied-representation lemma as a solution.

The missing constructive step is a genuinely computational nonlinear source, generated from the ORIGINAL statement alone, for which all distinct valid witnesses recover the SAME precommitted path-scoped capability and where no public non-Boolean/rational/projective evaluation enables release, **together with** an actual straight-line QPT simulator for the whole correlated public distribution and an arbitrary-recovery-to-ORIGINAL-witness or independent PQ break reduction. This run does not reduce that obligation.

## Exact executed checker

The following JavaScript function was executed in the connected V8 execution environment, without browser/network/external literature. It is the same function published here. Run the function in Node/V8 and print the returned object to reproduce the captured output.

~~~javascript
function checker(){
  let checks=0;
  function ck(cond,msg){checks++;if(!cond)throw Error("assertion "+checks+" "+msg);}
  const pats=[1,2,3,4,5,6,7];
  const pop=z=>z.reduce((a,b)=>a+b*b,0);
  const l1=z=>z.reduce((a,b)=>a+Math.abs(b),0);
  const dot=(u,v)=>u.reduce((a,x,i)=>a+x*v[i],0);
  const mod=(x,q)=>((x%q)+q)%q;
  const center=(x,q)=>{let t=mod(x,q);return t>q/2?t-q:t;};
  function compile(n,clauses){
    const m=clauses.length,N=2*n+7*m,rows=[],b=[];
    function row(){return Array(N).fill(0);}
    for(let i=0;i<n;i++){let r=row();r[2*i]=1;r[2*i+1]=1;rows.push(r);b.push(1);}
    for(let j=0;j<m;j++){
      let r=row();for(let p of pats)r[2*n+7*j+p-1]=1;rows.push(r);b.push(1);
      for(let k=0;k<3;k++){
        let t=row();for(let p of pats)if((p>>k)&1)t[2*n+7*j+p-1]=1;
        let [i,pos]=clauses[j][k];t[2*i+(pos?1:0)]-=1;rows.push(t);b.push(0);
      }
    }
    return {n,m,N,rows,b};
  }
  function valid(n,clauses,w){return clauses.every(cl=>cl.some(([i,pos])=>Number(w[i])===Number(pos)));}
  function repr(n,clauses,w){
    let z=Array(2*n+7*clauses.length).fill(0);
    for(let i=0;i<n;i++)z[2*i+(w[i]?1:0)]=1;
    clauses.forEach((cl,j)=>{let p=0;cl.forEach(([i,pos],k)=>{if(w[i]===Number(pos))p|=1<<k;});if(p)z[2*n+7*j+p-1]=1;});
    return z;
  }
  function frac4(n,m){
    let z=Array(2*n+7*m).fill(0);
    for(let i=0;i<n;i++){z[2*i]=2;z[2*i+1]=2;}
    for(let j=0;j<m;j++)for(let p of [1,2,4,7])z[2*n+7*j+p-1]=1;
    return z;
  }
  let assignmentTests=0,fractionalTests=0;
  for(let n of [1,2,3]){
    for(let signs=0;signs<8;signs++){
      let cl=Array.from({length:3},(_,k)=>[k%n,Boolean((signs>>k)&1)]);
      const C=compile(n,[cl]),y=frac4(n,1);
      for(let i=0;i<C.rows.length;i++){ck(dot(C.rows[i],y)===4*C.b[i],"fractional equation");fractionalTests++;}
      ck(l1(y)===4*(n+1),"fractional l1");
      ck(pop(y)===16*(n/2+1/4),"fractional l2");
      for(let mask=0;mask<(1<<n);mask++){
        let w=Array.from({length:n},(_,i)=>(mask>>i)&1);
        if(!valid(n,[cl],w))continue;
        let z=repr(n,[cl],w);
        for(let i=0;i<C.rows.length;i++)ck(dot(C.rows[i],z)===C.b[i],"witness Ax=b");
        ck(pop(z)===n+1&&l1(z)===n+1,"integer one hot");
        assignmentTests++;
      }
    }
  }
  const P=Array.from({length:3},()=>[0,true]);
  const N=Array.from({length:3},()=>[0,false]);
  const C=compile(1,[P,N]),y=frac4(1,2),B=3;
  ck(!valid(1,[P,N],[0])&&!valid(1,[P,N],[1]),"fixed FALSE instance");
  for(let i=0;i<C.rows.length;i++)ck(dot(C.rows[i],y)===4*C.b[i],"FALSE 4b representation");
  ck(pop(y)===16&&l1(y)===12&&l1(y)/4===B,"false normalized norm");
  let seed=0x638bc71a;
  function rand(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;}
  const q=769,Delta=64,iterations=2048;
  let recoveries=0,maxErr=0;
  for(let i=0;i<iterations;i++){
    let r=C.rows.map(()=>rand()%q),e=Array.from({length:C.N},()=>rand()%3-1),e0=rand()%3-1;
    let key=i%2;
    let cipher=Array.from({length:C.N},(_,j)=>mod(C.rows.reduce((a,row,h)=>a+row[j]*r[h],0)+e[j],q));
    let phase=mod(dot(C.b,r)+Delta*key+e0,q);
    let residual=center(4*phase-dot(y,cipher),q),expected=4*Delta*key;
    let error=4*e0-dot(y,e);
    ck(residual===expected+error,"joint algebraic exact error");
    ck(Math.abs(error)<=4*(1+B),"uniform noise bound");
    let recovered=Math.abs(residual-4*Delta)<Math.abs(residual)?1:0;
    ck(recovered===key,"false source unauthorized bit recovery");
    recoveries++;maxErr=Math.max(maxErr,Math.abs(error));
  }
  return {run:"R161-ONEHOT-INTEGRAL-LWE-RELEASE-20261108",status:"no security advance; universal FALSE rational projective opening",assertions:checks,clause_sign_cases:24,valid_witness_cases:assignmentTests,fractional_linear_checks:fractionalTests,false_instance:"(x∨x∨x) ∧ (¬x∨¬x∨¬x)",matrix_rows:C.rows.length,matrix_columns:C.N,normalized_l1:l1(y)/4,normalized_l2_squared:pop(y)/16,valid_integral_norm_squared:B,q,delta:Delta,noise_bound:1,simulated_false_recoveries:recoveries,max_observed_scaled_error:maxErr};
}
console.log(JSON.stringify(checker(),null,2));
~~~

## Captured executed output

~~~json
{
  "run": "R161-ONEHOT-INTEGRAL-LWE-RELEASE-20261108",
  "status": "no security advance; universal FALSE rational projective opening",
  "assertions": 7075,
  "clause_sign_cases": 24,
  "valid_witness_cases": 98,
  "fractional_linear_checks": 144,
  "false_instance": "(x∨x∨x) ∧ (¬x∨¬x∨¬x)",
  "matrix_rows": 9,
  "matrix_columns": 16,
  "normalized_l1": 3,
  "normalized_l2_squared": 1,
  "valid_integral_norm_squared": 3,
  "q": 769,
  "delta": 64,
  "noise_bound": 1,
  "simulated_false_recoveries": 2048,
  "max_observed_scaled_error": 14
}
~~~
