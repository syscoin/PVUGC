# R89: exact ORIGINAL-to-bounded-error source compiler; public release breaks

**Result: no positive SECURE witness-KEM advance.** This newly constructed source handles 3CNF functional correctness for every distinct valid ORIGINAL witness, but its entire pre-signed capability is publicly recoverable without a witness. The attempted affine-key blinding repair fails as well. This is NOT an ordinary-QPT-LWE security proof, not the hard-TRUE arbitrary key-recovery -> ORIGINAL witness reduction, and not a secure successor to R88.

Run `R89-3CNF-BDD-SOURCE-COMPILER-20261105`; syscoin/PVUGC PR #1 open/draft/unmerged, branch `research/pq-wkem-validation-20260918`, verified starting SHA `f079c1206ab368b9bc74961ebeaa12e38c488080`, latest substantive ordinary comment 6659748224. Exact predecessor R88 Git blob `588f3753c77320e017a3210e26544736d009f909` and R83 blob `3f20422d7450a460bda28adf7e3862dcc8f41238` inspected. No web/external literature research.

## Exact classical-PPT source compiler and release

For a 3CNF F with n original variables and c clauses, define a public BDD-shaped source `(A,b)` over prime q>max(23,4m+4), with m=2n+2c, secret dimension d=n+c and centered error bound beta=1. Add to A for each Boolean variable z_i two identical unit-vector rows with public targets b=0 and b=1. The intersection of both centered error <=1 constraints forces z_i exactly 0 or 1 mod q, including all modular secret representatives. For each clause j introduce a slack t_j with a unit row target 1, forcing t_j in {0,1,2}. The final clause row has coefficients +3 for each positive literal occurrence, -3 for each negative occurrence, -3 on t_j, target 3(1-h), where h is its number of negative literals. Add coefficients for repeated literals. Its residual <=1 forces the *exact integer* equation `sum of three literal truth values = 1+t_j`: nonzero discrepancies multiply 3 and cannot wrap to a centered residue of magnitude <=1 when q>23.

Define `R_BDD((A,b),(s,e))` iff `b=A*s+e (mod q)` and each centered error has abs<=1. For each satisfying ORIGINAL assignment w, let s consist of w followed by t_j=(sum of clause truth values)-1; then e=b-As is bounded. Conversely **any** valid BDD source key s has the original w in its first n coordinates and that w satisfies every clause, so a supplied valid source key projects to the actual ORIGINAL witness. Distinct satisfying assignments have distinct short-error keys, with no canonical or common witness state. A standard witness-preserving circuit-to-3CNF frontend can extend the functional mapping to NP, but this frontend was not implemented/tested in R89, and must bind the full ORIGINAL claim, branch, UTXO, window, context and intended native verification key.

For a classical-PPT, witness-blind Build, select precommitted uniform seed T. Independently for each bit draw r_j uniform in {0,1}^m and publish `C_j=(u=A^T r_j,v=b^T r_j+Delta*T_j) mod q`, Delta=floor(q/2). Every valid ORIGINAL witness-derived s computes `v-s^T u=e^T r+Delta*T_j`, with `|e^T r|<=m<q/4-1`, hence all valid ORIGINAL witnesses release the same exact T. A prospective full release uses a native pre-signature sigma on the frozen challenge message, disjoint P and checking seed B from a QPT-secure PRG(T), Dsig=sigma XOR P and acyclic CK/Aux dependent on B,Dsig,C,context and related capsule roots. The checked signature, PRG and CK/Aux use **insecure toy deterministic functions** only to verify the full-public leakage implication.

## The direct public break (TRUE AND FALSE)

The generated public b has target entries from 0,1,1 and clause values 3(1-h) in {-6,-3,0,3}. Consequently `||b||_1<=n+7c`. In the q=257 test, n=3 and c<=4 gives `||b||_1<=31<q/8`. Thus every b^T r is publicly known to lie in an interval of radius <q/8 around 0, so **v alone** is enough to round exactly to the seed bit T_j, without u, any source key, a satisfying assignment, or ORIGINAL evidence. Once T is public, P, B and sigma=Dsig XOR P become public; so do the checking-key/auxiliary correlations. This is an explicit deterministic classical PPT break against true or false source statements, not a no-attack-found toy. A QPT attacker can run it too, so no ordinary-LWE source security reduction can prove this public distribution secure.

Attempted repair: affine blind b'=b+A*t with secret random t and erase t. Every original witness still opens under shifted key s'=s+t, but each variable's first gadget row directly discloses t_i=b'_(i,first); each slack row discloses t_(n+j)=b'_(slack,j)-1. Thus a public attacker reconstructs t, subtracts t^T u from the blinded v, and performs the same v-only rounding. A public basis change is equally inadequate. The failure is preserved as a construction test, NOT advertised as a completed repair.

## Assumptions / quantum and composition limits

The 3CNF/BDD functional equivalence and all-witness same-capability correctness are algebraic. The public break is unconditional for the stated parameters. QPT security assumptions are **not applicable** to this deterministic nonuniform A,b, which is not an honestly sampled LWE public key. The checker uses toy q=257, 12-bit seed and fake native signature/PRG/checking hashes. It does not test QPT hardness, 128-bit parameters, full arbitrary-NP conversion, SOURCE SYS/BTC authentication, malicious/retained setup secrets, aborts, pre-funding DA, same-root/related capsule openings, arbitrary adversarial quantum advice, or the conditional Bitcoin no-EC-key-path/PQ-signature graph. Generic false-instance full-public security and arbitrary unauthorized already-presigned final-key recovery -> ORIGINAL witness or independently justified QPT break remain UNSOLVED. A supplied BDD key -> ORIGINAL witness is specifically insufficient.

**Next exact missing equation:** find classical-PPT Comp(R_original,x) producing an actual statement-dependent source and real ordinary-QPT-LWE challenge simulator jointly (including capsule, CK, AUX, context and related capsules) without seeing any ORIGINAL witness, while ALL ORIGINAL witnesses can open the SAME capability and ANY arbitrary QPT unauthorized already-presigned capability recovery yields an ORIGINAL witness or independent PQ break. This candidate satisfies only functional mapping, not full-public hiding or extraction. Do not disable the research automation.

## Exact executed V8 checker

```javascript
function R89(){
  const q=257,Delta=128;let checks=0,state=0x89115;
  let counts={formulas:0,candidates:0,validKeys:0,openings:0,publicBitRecoveries:0,fullViewRecoveries:0,affineBreaks:0,falseFormulas:0,modularChecks:0};
  const ok=(v,msg)=>{checks++;if(!v)throw Error("Assertion "+checks+": "+msg)};
  const rnd=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state};
  const centered=z=>(((z%q)+q+128)%q)-128;
  const H=(h,arr)=>arr.reduce((acc,z)=>(Math.imul(acc^z,1664525)+1013904223)>>>0,h>>>0);
  function compile(n,F){
    let A=[],b=[],d=n+F.length;
    function add(coeff,val){let row=Array(d).fill(0);for(const [k,v] of Object.entries(coeff))row[Number(k)]+=v;A.push(row);b.push(val)}
    for(let i=0;i<n;i++){add({[i]:1},0);add({[i]:1},1)}
    for(let j=0;j<F.length;j++){
      add({[n+j]:1},1);
      let coeff={[n+j]:-3},h=0;
      for(let lit of F[j]){let i=Math.abs(lit)-1;coeff[i]=(coeff[i]||0)+3*(lit>0?1:-1);if(lit<0)h++}
      add(coeff,3*(1-h));
    }
    return {A,b};
  }
  const sat=(F,w)=>F.every(cl=>cl.some(l=>l>0?w[l-1]===1:w[-l-1]===0));
  const key=(A,b,s)=>b.every((v,i)=>Math.abs(centered(v-A[i].reduce((a,z,j)=>a+z*s[j],0)))<=1);
  const encrypt=(A,b,bit,r)=>({u:A[0].map((_,k)=>A.reduce((a,row,i)=>a+row[k]*r[i],0)),v:((b.reduce((a,x,i)=>a+x*r[i],0)+Delta*bit)%q+q)%q});
  const op=(ct,s)=>{let y=centered(ct.v-ct.u.reduce((a,z,j)=>a+z*s[j],0));return +(Math.abs(centered(y-Delta))<Math.abs(y))};
  const pub=v=>+(Math.abs(centered(v-Delta))<Math.abs(centered(v)));
  for(let ix=0;ix<80;ix++){
    let n=3,c=1+rnd()%4,F=[];
    for(let j=0;j<c;j++){let cl=[];for(let k=0;k<3;k++){let v=1+rnd()%3;cl.push((rnd()&1)?v:-v)}F.push(cl)}
    if(ix%9===0)F=[[1,1,1],[-1,-1,-1]];
    let {A,b}=compile(n,F),m=b.length,keys=[];
    ok(m===2*n+2*F.length,"gadget rows");
    ok(m<q/4-1,"all witness decoding margin");
    ok(b.reduce((a,z)=>a+Math.abs(z),0)<q/8,"v-only public break bound");
    counts.formulas++;
    for(let bits=0;bits<8;bits++){
      let w=Array.from({length:n},(_,i)=>(bits>>i)&1);
      for(let k=0;k<3**F.length;k++){
        let x=k,t=[];for(let j=0;j<F.length;j++){t.push(x%3);x=Math.floor(x/3)}
        let s=w.concat(t),valid=key(A,b,s);
        let expected=sat(F,w)&&F.every((cl,j)=>t[j]===cl.reduce((v,l)=>v+(l>0?w[l-1]:1-w[-l-1]),0)-1);
        ok(valid===expected,"BDD source iff exact ORIGINAL satisfying witness");
        counts.candidates++;
        if(valid){keys.push(s);counts.validKeys++}
      }
    }
    if(!keys.length)counts.falseFormulas++;
    let T=Array.from({length:12},()=>rnd()&1),cts=[];
    for(const bit of T){let r=Array.from({length:m},()=>rnd()&1),ct=encrypt(A,b,bit,r);cts.push(ct);ok(pub(ct.v)===bit,"no witness public bit recovery");counts.publicBitRecoveries++}
    for(const s of keys){ok(cts.every((ct,i)=>op(ct,s)===T[i]),"all valid ORIGINAL witnesses open identical T");counts.openings++}
    let P=H(17,T),B=H(29,T),sig=rnd()|0,D=sig^P,ctHash=H(101,cts.map(ct=>ct.v));
    let CK=H(23,[B,D,ctHash,ix]),Aux=H(41,[B,CK,D,ix]),guessed=cts.map(ct=>pub(ct.v));
    ok(((D^H(17,guessed))|0)===sig
      &&CK===H(23,[H(29,guessed),D,ctHash,ix])
      &&Aux===H(41,[H(29,guessed),CK,D,ix]),"already-presigned native toy capability and public CK/Aux recovered");
    counts.fullViewRecoveries++;
    let t=Array.from({length:n+F.length},()=>rnd()%q);
    let bp=b.map((x,i)=>((x+A[i].reduce((a,z,j)=>a+z*t[j],0))%q+q)%q);
    let recovered=Array(n+F.length).fill(0);
    for(let i=0;i<n;i++)recovered[i]=bp[2*i];
    for(let j=0;j<F.length;j++)recovered[n+j]=(bp[2*n+2*j]-1+q)%q;
    ok(recovered.every((v,i)=>v===t[i]),"affine mask publicly recoverable");
    let r=Array.from({length:m},()=>rnd()&1),ct=encrypt(A,bp,T[0],r);
    let unmasked=((ct.v-ct.u.reduce((a,v,j)=>a+v*recovered[j],0))%q+q)%q;
    ok(pub(unmasked)===T[0],"affine source repaired attempt publicly decrypts");
    counts.affineBreaks++;
  }
  let {A,b}=compile(1,[[1,1,1]]);
  for(let z=0;z<q;z++){ok(key(A,b,[z,2])===(z===1),"no modular nonboolean shortcuts");counts.modularChecks++}
  return {run:"R89-3CNF-BDD-SOURCE-COMPILER-20261105",status:"NO_SECURE_WKEM_ADVANCE",q,beta:1,assertions:checks,counts};
}
console.log(JSON.stringify(R89(),null,2));
```

## Captured execution
```json
{
  "run": "R89-3CNF-BDD-SOURCE-COMPILER-20261105",
  "status": "NO_SECURE_WKEM_ADVANCE",
  "q": 257,
  "beta": 1,
  "assertions": 4901,
  "counts": {
    "formulas": 80,
    "candidates": 2784,
    "validKeys": 420,
    "openings": 420,
    "publicBitRecoveries": 960,
    "fullViewRecoveries": 80,
    "affineBreaks": 80,
    "falseFormulas": 9,
    "modularChecks": 257
  }
}
```

A prior expanded checker had a test-fixture bug when a hardcoded contradictory clause set replaced a formula without updating c; a subsequent expanded run had a JS signed/unsigned XOR comparison bug. Both were corrected before this exact checker ran. Local Python/container encountered transient redis ResponseError/TooManyRequestsError. These are execution/tool errors, not GitHub safety denials. No external research.
