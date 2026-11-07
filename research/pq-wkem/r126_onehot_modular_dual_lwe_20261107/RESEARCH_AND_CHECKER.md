# R126 — One-hot modular dual-LWE ORIGINAL source: exact witness correctness but universal public false opener

**Classification:** Rejected candidate. No secure ORIGINAL witness-KEM, no generic false-instance hiding, no arbitrary-recovery extraction. This is a bounded OFFLINE source construction and adversarial test, preserved for continuity; **do not notify the user for a routine negative result**.

**Continuity:** syscoin/PVUGC PR #1, draft/unmerged, branch research/pq-wkem-validation-20260918, observed starting SHA 6dac106716452e1282cded1a7fec72c880a4a47e. Latest PR substantive ordinary comment 6698876958 describes the earlier R122A failure; newest R125 at head diagnoses linear real Gaussian public GLS recovery. This candidate instead tests modular arithmetic and exact one-hot integrality to address the fractional/invalid affine-representation issue, not covariance tuning, packing or size.

## Concrete algorithm

For ORIGINAL 3CNF x with n variables and m clauses, set P=n+2m. Allocate one pair of integer coordinates (z_i^1,z_i^0) per original variable, plus two slack-bit pairs per clause (P pairs total, 2P coordinates). Define A in Z^((P+m)×2P) and delta in Z^(P+m):

* Each pair consistency row requires z_i^1+z_i^0=1.
* Each clause j with its 3 literal-indicator coordinates L_1,L_2,L_3 requires L_1+L_2+L_3+s_{j,1}^1+2s_{j,2}^1=4.
* delta contains P ones and m fours.
* A witness w with satisfying truth bits gives each pair (1,0) or (0,1). If the clause has k satisfied literals, the slack bits (s1,s2) are (1,1) for k=1, (0,1) for k=2, and (1,0) for k=3.

**Exact representation lemma (proved):** Every integer vector z satisfying Az=delta and ||z||_2^2 ≤ P determines an ORIGINAL 3CNF satisfying assignment. Indeed each integral pair with sum 1 has squared norm at least 1, with equality iff binary; P pairs force every pair binary, and an all-false clause would demand s1+2s2=4, impossible for binary slack bits. Conversely every ORIGINAL valid witness supplies such a vector of squared norm exactly P. Different original witnesses remain distinct vectors.

A candidate **classical** source setup for each hidden bit B∈{0,1} chooses r uniformly in Z_q^(P+m), independent bounded errors e∈[-eta,eta]^(2P), e0∈[-eta,eta], and publishes

    U=A^T r+e (mod q),   V=delta^T r+e0+B floor(q/2) (mod q).

The off-chain opener for a vector z with Az=delta uses residual V-z^T U mod q and nearest of 0 and floor(q/2). For any ORIGINAL valid w and q>4eta(P+1)+1, the residual noise is bounded by eta(P+1), so the same precommitted bit B is recovered on EVERY supported error tape. Multiple such bits could mask a frozen native signature, bound to relation identity/claim/UTXO/branch/anchors/window/context/VK, but this is not pursued after the source break. Honest algorithms are classical PPT for polynomial n,m and log q.

## Universal public false attack

**The tight integer-norm lemma does not imply security against arbitrary public decryption algorithms.** For every 3CNF x and ANY publicly selected Boolean assignment a (even one that violates clauses), calculate the number k_j in {0,1,2,3} of satisfied literals in clause j and set its two slack-bit first coordinates to:

    k=0 -> (s1,s2)=(0,2)
    k=1 -> (1,1)
    k=2 -> (0,1)
    k=3 -> (1,0).

For each pair set its complementary second coordinate to 1 minus the first. Then the PUBLIC, polynomial-time computable z_bad obeys Az_bad=delta EXACTLY, even for fixed-FALSE x. If u is the number of clauses unsatisfied by assignment a, then

    ||z_bad||_2^2 = P+4u,
    ||z_bad||_1   = P+2u,    0≤u≤m.

Every unsatisfied clause contributes exactly one nonbinary pair (2,-1). It is enough that q>4eta(P+2m+1)+1 to guarantee

    V-z_bad^T U = B floor(q/2) + (e0-z_bad^T e) mod q,
    |e0-z_bad^T e| ≤ eta(P+2u+1).

Therefore the publicly computed z_bad **deterministically recovers B for every supported noise tape**, independently of the actual satisfiability of x. In particular the fixed-FALSE formula (x∨x∨x)∧(¬x∨¬x∨¬x), with one original variable, two clauses, P=5, admits norm-square P+4=9 false opening versus valid norm-square P=5. Taking q=65521 and eta=1 yields a huge safety margin for the **ATTACK**, not cryptographic hiding. Multiple related capsules and arbitrary CK/Aux/J/context cannot repair an already-leaking public (U,V) marginal; a QPT adversary can run the same classical PPT attack coherently or classically.

This source cannot be repaired by merely checking ||z||≤sqrt(P) inside the official Open algorithm: the adversary never has to submit its internal z to Open, and can compute its own linear residual. Merely making the modulus larger makes the attack more reliable. Repeating ciphertexts or hashing their leaked bits does not hide a pad if all its constituents can be recovered. Randomizing/publicly mixing A on its left preserves all public Az=delta relations. No ordinary QPT-LWE assumption applies automatically to this highly structured A(x), and no full-public QPT simulator/reduction has been instantiated.

## Exact source, tests and scope

The full-public view would contain x, A,delta,U,V, native VK, intended challenge/claim/branch/context/anchor identifiers, checking keys J/CK, Aux, related capsules, and allowed opening/auxiliary correlations. This attack uses only the public U,V,A,delta and does not assume source secrets, signatures, adversary-supplied representation, or classical rewinding. Native forgery extraction, malicious N-of-N ceremony/abort, graph/censorship, quantitative PQ parameter security, and conditional Bitcoin native-PQ endpoint all remain unsolved.

**Executed checker:** the exact JavaScript function below ran within the connector V8 isolate before publication, with deterministic seeded fixtures. It tested seven distinct satisfying ORIGINAL witness paths over 256 real toy ciphertexts, 1024 public false decryptions, and 100 arbitrary random 3CNF input constructions. Independent LOCAL Python standard-library checker ran 10,350 assertions and captured its output. The checker only verifies finite integer identities and functional encryption/decryption; the displayed all-noise attack follows from the algebraic bound, not sampling. The tests are not a QPT-hardness experiment.

~~~javascript
function r126Checker(){
  const q=65521,eta=1;
  let seed=126,checks=0;
  const rnd=(n)=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};
  const ok=(b,s)=>{checks++;if(!b)throw new Error(s+" check "+checks)};
  const dot=(a,b)=>a.reduce((sum,x,i)=>sum+x*b[i],0);
  function make(n,cls){
    const m=cls.length,P=n+2*m,N=2*P;
    const A=Array.from({length:P+m},()=>Array(N).fill(0));
    const d=Array(P).fill(1).concat(Array(m).fill(4));
    for(let i=0;i<P;i++){A[i][2*i]=1;A[i][2*i+1]=1;}
    cls.forEach((cl,j)=>{
      for(const [i,pos] of cl)A[P+j][2*i+(pos?0:1)]++;
      A[P+j][2*(n+2*j)]=1;A[P+j][2*(n+2*j+1)]=2;
    });
    return {A,d,P,m,n,cls};
  }
  function repr(x,truth){
    const z=[];let u=0;
    for(const t of truth)z.push(t,1-t);
    for(const cl of x.cls){
      const k=cl.reduce((tot,[i,pos])=>tot+(pos?truth[i]:1-truth[i]),0);
      if(k===0)u++;
      const pair=[[0,2],[1,1],[0,1],[1,0]][k];
      for(const b of pair)z.push(b,1-b);
    }
    return {z,u};
  }
  const matvec=(A,z)=>A.map(r=>dot(r,z));
  function cipher(x,B){
    const s=x.A.map(()=>rnd(q)),e=x.A[0].map(()=>rnd(3)-1),e0=rnd(3)-1;
    const U=x.A[0].map((_,j)=>(x.A.reduce((acc,row,i)=>acc+row[j]*s[i],0)+e[j])%q);
    const V=(dot(x.d,s)+e0+B*Math.floor(q/2))%q;
    return {U,V,e,e0};
  }
  function decrypt(z,c){
    let r=((c.V-dot(z,c.U))%q+q)%q,t=Math.floor(q/2);
    const d0=Math.min(r,q-r),d1=Math.min((r-t+q)%q,(t-r+q)%q);
    return d1<d0?1:0;
  }
  const truex=make(3,[[[0,true],[1,true],[2,true]]]);
  let valid=0;
  for(let v=0;v<8;v++){
    const bits=[v&1,(v>>1)&1,(v>>2)&1],{z,u}=repr(truex,bits);
    ok(JSON.stringify(matvec(truex.A,z))===JSON.stringify(truex.d),"source equality");
    ok(dot(z,z)===truex.P+4*u,"norm certificate");
    if(u===0)valid++;
  }
  ok(valid===7,"number valid");
  for(const B of [0,1])for(let i=0;i<128;i++){
    const c=cipher(truex,B);
    for(let v=1;v<8;v++){
      const {z,u}=repr(truex,[v&1,(v>>1)&1,(v>>2)&1]);
      ok(u===0&&decrypt(z,c)===B,"every valid witness SAME bit");
    }
  }
  const falsex=make(1,[[[0,true],[0,true],[0,true]],[[0,false],[0,false],[0,false]]]);
  ok(falsex.P===5,"false pairs");
  for(let v=0;v<=1;v++){
    const {z,u}=repr(falsex,[v]);
    ok(u===1,"formula unsatisfiable");
    ok(JSON.stringify(matvec(falsex.A,z))===JSON.stringify(falsex.d),"false affine source");
    ok(dot(z,z)===falsex.P+4,"tight norm gate misses false z");
    ok(z.reduce((s,a)=>s+Math.abs(a),0)===falsex.P+2,"false l1");
    ok(4*(1+falsex.P+2*falsex.m)<q-1,"bounded noise tape");
    for(const B of [0,1])for(let i=0;i<256;i++){
      const c=cipher(falsex,B);
      ok(decrypt(z,c)===B,"false public key recovery");
    }
  }
  for(let n=1;n<=4;n++)for(let j=0;j<25;j++){
    const m=1+rnd(7);
    const clauses=Array.from({length:m},()=>Array.from({length:3},()=>[rnd(n),!!rnd(2)]));
    const x=make(n,clauses),truth=Array.from({length:n},()=>rnd(2)),{z,u}=repr(x,truth);
    ok(JSON.stringify(matvec(x.A,z))===JSON.stringify(x.d),"general integer source");
    ok(dot(z,z)===x.P+4*u,"general exact norm");
    ok(z.reduce((s,a)=>s+Math.abs(a),0)===x.P+2*u,"general exact l1");
    ok(4*(1+x.P+2*x.m)<q-1,"general setup correctness bound");
    for(const B of [0,1])ok(decrypt(z,cipher(x,B))===B,"general chosen assignment decrypts even if invalid");
  }
  return {run:"R126-ONEHOT-MODULAR-DUAL-LWE-20261107",checks,trueWitnesses:valid,falsePairs:falsex.P,conclusion:"Rejected: public invalid integer z recovers hidden bit from a false ORIGINAL 3CNF for every bounded error tape"};
}
const captured = r126Checker();
console.log(JSON.stringify(captured));
~~~

**Captured JavaScript output**

~~~json
{
  "run": "R126-ONEHOT-MODULAR-DUAL-LWE-20261107",
  "checks": 3444,
  "trueWitnesses": 7,
  "falsePairs": 5,
  "conclusion": "Rejected: public invalid integer z recovers hidden bit from a false ORIGINAL 3CNF for every bounded error tape"
}
~~~

**Independent LOCAL checker provenance:** checker.py SHA-256 3a6b9006ed3420fa06482b4793c0ed52a07359565882e9eb35160e1402f5eb5e, captured.json SHA-256 2465fa8fcbfb1fe59b38a704b15410ab62d99537ee7bcd34b816c4a2ce5a30db. Independent local script and output are not claimed published. No external literature or internet research, other repository writes, PR review/merge or deploy.

## Honest next handoff

Reject this one-hot modular dual-LWE source. The exact short-integer → ORIGINAL-witness lemma is sound *only for a supplied vector within the tight norm threshold*; it has no recovery-to-representation reduction and cannot constrain a different public linear decoder. The next viable candidate must make **all efficiently computable invalid openings** hide the payload (not only forbid short invalid witnesses) and provide a joint source-dependent challenge simulator for the full public view under independently justified QPT assumptions. A nonlinear/discrete opening operation is a candidate only with an explicit construction and proof, not by naming it. No generic witness-KEM security claim is made.
