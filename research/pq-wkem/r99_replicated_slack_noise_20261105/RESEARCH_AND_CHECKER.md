# R99 — Repeated clause/slack rows do not repair near-key release (NO constructive secure WKEM advance)

**Run ID:** `R99-REPLICATED-SLACK-LWE-20261105`. **Continuity:** `syscoin/PVUGC#1` open/draft/unmerged; branch `research/pq-wkem-validation-20260918`; starting SHA `86e4f0be279177ae6e71c468a0769db93dfba731`; exact predecessor R98 blob `a13db65cd8a39a4519a5b71327dbdc22164d3c3e`, ordinary substantive PR comment `6672663121`. Offline mathematics; no external literature/web.

## Proposed constructive repair and its explicit release
Continue **only** R98's witness-blind linear 3CNF source compiler. A proposed integrity-gap repair repeats **every** 3CNF row R times and increases prime q with R, attempting to push invalid near-keys outside Regev's rounding margin while preserving full all-witness correctness. Fix beta=1, gamma=25 and per-coordinate independent Regev coins r in {-3,-2,-1,0,1,2,3}. For each seed bit t, Build publishes `u=A_R^T r (mod q)`, `v=b_R^T r + floor(q/2)*t (mod q)`, and the usual precommitted seed-masked native signature and all bound CK/Aux/context/related-capsule records. The builder knows no ORIGINAL witness. Open checks the ORIGINAL 3CNF-derived source key, then computes `z=v-<s,u>` and rounds to recover the same T and native capability. This is a concrete release algorithm, but the security repair **fails**.

Consider ORIGINAL FALSE statement `F=(x OR x OR x) AND (NOT x OR NOT x OR NOT x)`. The original R98 six-by-three source is `A=[[1,0,0],[1,0,0],[0,1,0],[225,-75,0],[0,0,1],[-225,0,-75]]`, `b=[0,1,1,75,1,-150]`. Repeat each row R times. The source bound is `||b_R-A_R s||_infinity<=1`. For all primes q>450, duplicated variable rows force x∈{0,1}, slack rows force t0,t1∈{0,1,2}, and the mutually contradictory 3CNF clauses cannot both have residual ≤1. Therefore the full ORIGINAL statement is FALSE and there is **no accepted bounded-error source secret**, including modular candidates.

An adversary instead computes the public **invalid** vector `s*=(0,-1,2)`; its six-row residual is `e*=(0,1,2,0,-1,0)`, repeated R times. It fails the source checker, but that checker can be bypassed. For the actual public capsule it computes `z*=v-<s*,u> = floor(q/2)*t + Z (mod q)`, where `Z=sum_i e*_i r_i` is a sum of **3R independent nonzero** septenary terms (2R terms with coefficient magnitude 1, R with magnitude 2). Therefore `sum_i (e*_i)^2=6R` and `|Z|<=12R`.

Choose `q=nextPrime(max(32R,450))` for R>=16. For the satisfying single-positive-clause TRUE control, a valid source has residual `e_true=(-1,0,-1,0)` repeated R times, so `|<e_true,r>|<=6R < q/4-1`; **every genuine witness decrypts all coin tapes correctly**. The invalid fake key has worst-case bound `12R > q/4-1`, defeating R98's earlier deterministic worst-case near-key criterion. That is the *intended* repair. But public fake decryption succeeds whenever `|Z| < q/4-1`. Hoeffding for independent symmetric bounded terms yields

`Pr[public near-key bit failure] <= 2 exp(-(q/4-1)^2/(18 sum_i e*_i^2)) = 2 exp(-(q/4-1)^2/(108R))`.

For q>=32R, this is `exp(-Omega(R))`. In particular, taking polynomial R at least linear in security parameter lets a classical attacker recover **all κ independently encrypted root bits** with probability at least `1-2κ exp(-Omega(R))`; its public bit rounding uses no accepted witness, no source secret, no challenge simulator and no SourceOpen. Once T is recovered, ordinary deterministic PRG(T)-masked pre-signature, CK/Aux, all context/related-capsule correlations are recomputable. This is a **classical PPT** attack and therefore applies to arbitrary QPT adversaries too. It defeats this row-repetition/modulus-gap repair for the FALSE instance while satisfying the positive TRUE-control functional margin; not a general no-go for nonlinear sources or generic NP WE.

## Exact bounded computation
Executed V8 BigInt checker below performs **exact integer** convolution of the 3R nonzero uniform septenary random variables, with counts represented as integers and denominator `7^(3R)`. The reported decimal scientific values are rounded *only after* exact counting; the Hoeffding upper bound is independent mathematical analysis. The rows with zero residual have no effect on Z, and no simulation or sampling is used. It also checks prime q, full modular source soundness gadget candidates, genuine TRUE-control all-coin margin, fake near-key residual, and count normalization. These finite checks do not establish PQ security.

```javascript
function runR99(){
 const Rs=[16,32,64,128], gamma=25, beta=1, rho=3, bitCount=256;let assertions=0;
 const ok=(v,s)=>{assertions++;if(!v)throw Error("R99 assertion "+assertions+": "+s)};
 const mod=(a,q)=>(a%q+q)%q;
 const center=(a,q)=>{const x=mod(a,q);return x>Math.floor(q/2)?x-q:x};
 const dot=(a,b)=>a.reduce((sum,v,i)=>sum+v*b[i],0);
 const isPrime=n=>{if(n<2)return false;for(let d=2;d*d<=n;d++)if(n%d===0)return false;return true};
 const sci=(a,b)=>{if(a===0n)return "0";const x=a.toString(),y=b.toString();return ((Number(x.slice(0,15))/Number(y.slice(0,15)))*10**(x.length-y.length)).toExponential(8)};
 function dist(R){let c=[1n],lo=0;for(const e of [...Array(2*R).fill(1),...Array(R).fill(2)]){const next=Array(c.length+6*e).fill(0n);for(let i=0;i<c.length;i++)if(c[i]!==0n)for(let r=-3;r<=3;r++)next[i+3*e+r*e]+=c[i];c=next;lo-=3*e;}return {c,lo,den:7n**BigInt(3*R)};}
 const results=[];
 for(const R of Rs){
  const q=(()=>{let j=Math.max(32*R+1,451);while(!isPrime(j))j++;return j})();
  ok(isPrime(q)&&q>450&&q>32*R,"prime no clause alias and scalable modulus");
  const A=[[1,0,0],[1,0,0],[0,1,0],[9*gamma,-3*gamma,0],[0,0,1],[-9*gamma,0,-3*gamma]];
  const b=[0,1,1,3*gamma,1,-6*gamma],fake=[0,-1,2];
  const e=A.map((a,i)=>center(b[i]-dot(a,fake),q));
  ok(JSON.stringify(e)===JSON.stringify([0,1,2,0,-1,0]),"invalid public near-key residual");
  const at=[[1,0],[1,0],[0,1],[9*gamma,-3*gamma]],bt=[0,1,1,3*gamma],st=[1,2];
  const good=at.map((a,i)=>center(bt[i]-dot(a,st),q));
  ok(JSON.stringify(good)===JSON.stringify([-1,0,-1,0]),"valid witness control residual");
  const vars=[];for(let z=0;z<q;z++)if(Math.abs(center(-z,q))<=beta&&Math.abs(center(1-z,q))<=beta)vars.push(z);
  ok(JSON.stringify(vars)==="[0,1]","unit pairs force Boolean variable over whole field");
  const slack=[];for(let z=0;z<q;z++)if(Math.abs(center(1-z,q))<=beta)slack.push(z);
  ok(JSON.stringify(slack)==="[0,1,2]","slack small interval");
  for(const x of vars)for(const t0 of slack)for(const t1 of slack){
   const s=[x,t0,t1];
   ok(A.some((row,i)=>Math.abs(center(b[i]-dot(row,s),q))>beta),"contradictory original FALSE has no accepted bounded-error key");
  }
  const threshold=Math.floor(q/4)-1;
  ok(rho*2*R<q/4-1,"all-coin TRUE decoding exact for all r");
  ok(rho*4*R>q/4-1,"old deterministic public near-key sufficient condition deliberately fails");
  const d=dist(R),total=d.c.reduce((a,v)=>a+v,0n);
  ok(total===d.den,"exact independent septenary coin count");
  ok(d.lo===-12*R&&d.c.length===24*R+1,"integer DP support and indexing");
  let failures=0n;for(let i=0;i<d.c.length;i++)if(Math.abs(d.lo+i)>threshold)failures+=d.c[i];
  ok(failures>0n&&failures<d.den,"nonzero but tiny public near-key rounding failures");
  const h=2*Math.exp(-((q/4-1)**2)/(108*R));
  const approx=Number(sci(failures,d.den));
  ok(approx<h,"Hoeffding valid as upper bound on tail");
  results.push({R,q,rows:6*R,d:3,trueMaxError:6*R,falseNearKeyMaxError:12*R,
   quarterMargin:q/4-1,publicNearKeyFailProbabilityExactRatioApprox:sci(failures,d.den),
   honestAllCoinsCorrect:true,falseSourceHasNoValidKey:true,
   publicNearKeyFull256BitRootFailureUpperBound:(bitCount*approx).toExponential(8),
   hoeffdingPerBitUpperBound:h.toExponential(8),
   numeratorDecimalDigits:failures.toString().length,denominatorDecimalDigits:d.den.toString().length});
 }
 return {run:"R99-REPLICATED-SLACK-LWE-20261105",status:"NO_POSITIVE_SECURE_WKEM_ADVANCE",
  assertions,model:"witness-blind repeated R98 gadget, q prime > 32R, rho=3, beta=1, gamma=25, original FALSE contradictory 3CNF",
  proof:"TRUE control satisfies deterministic all-coins error margin; ORIGINAL FALSE has no accepted source; invalid publicly computable near-key decrypts almost certainly by concentration even outside worst-case margin",
  results,scope:"exact bigint finite dynamic programming and Hoeffding; no QPT security, no arbitrary NP source, no security repair"};
}
console.log(JSON.stringify(runR99(),null,2));
```

### Exact captured output
```json
{
  "run": "R99-REPLICATED-SLACK-LWE-20261105",
  "status": "NO_POSITIVE_SECURE_WKEM_ADVANCE",
  "assertions": 116,
  "model": "witness-blind repeated R98 gadget, q prime > 32R, rho=3, beta=1, gamma=25, original FALSE contradictory 3CNF",
  "proof": "TRUE control satisfies deterministic all-coins error margin; ORIGINAL FALSE has no accepted source; invalid publicly computable near-key decrypts almost certainly by concentration even outside worst-case margin",
  "results": [
    {
      "R": 16,
      "q": 521,
      "rows": 96,
      "d": 3,
      "trueMaxError": 96,
      "falseNearKeyMaxError": 192,
      "quarterMargin": 129.25,
      "publicNearKeyFailProbabilityExactRatioApprox": "7.20570980e-13",
      "honestAllCoinsCorrect": true,
      "falseSourceHasNoValidKey": true,
      "publicNearKeyFull256BitRootFailureUpperBound": "1.84466171e-10",
      "hoeffdingPerBitUpperBound": "1.26606879e-4",
      "numeratorDecimalDigits": 29,
      "denominatorDecimalDigits": 41
    },
    {
      "R": 32,
      "q": 1031,
      "rows": 192,
      "d": 3,
      "trueMaxError": 192,
      "falseNearKeyMaxError": 384,
      "quarterMargin": 256.75,
      "publicNearKeyFailProbabilityExactRatioApprox": "9.04474427e-24",
      "honestAllCoinsCorrect": true,
      "falseSourceHasNoValidKey": true,
      "publicNearKeyFull256BitRootFailureUpperBound": "2.31545453e-21",
      "hoeffdingPerBitUpperBound": "1.04038526e-8",
      "numeratorDecimalDigits": 59,
      "denominatorDecimalDigits": 82
    },
    {
      "R": 64,
      "q": 2053,
      "rows": 384,
      "d": 3,
      "trueMaxError": 384,
      "falseNearKeyMaxError": 768,
      "quarterMargin": 512.25,
      "publicNearKeyFailProbabilityExactRatioApprox": "7.49172630e-46",
      "honestAllCoinsCorrect": true,
      "falseSourceHasNoValidKey": true,
      "publicNearKeyFull256BitRootFailureUpperBound": "1.91788193e-43",
      "hoeffdingPerBitUpperBound": "6.51509477e-17",
      "numeratorDecimalDigits": 118,
      "denominatorDecimalDigits": 163
    },
    {
      "R": 128,
      "q": 4099,
      "rows": 768,
      "d": 3,
      "trueMaxError": 768,
      "falseNearKeyMaxError": 1536,
      "quarterMargin": 1023.75,
      "publicNearKeyFailProbabilityExactRatioApprox": "1.16343188e-89",
      "honestAllCoinsCorrect": true,
      "falseSourceHasNoValidKey": true,
      "publicNearKeyFull256BitRootFailureUpperBound": "2.97838561e-87",
      "hoeffdingPerBitUpperBound": "2.37176858e-33",
      "numeratorDecimalDigits": 236,
      "denominatorDecimalDigits": 325
    }
  ],
  "scope": "exact bigint finite dynamic programming and Hoeffding; no QPT security, no arbitrary NP source, no security repair"
}
```

## Adversary, joint-public output and precise remaining equation
The honest source/setup/evaluation are classical PPT. The counterexample uses only a uniform independent septenary encryption random tape, explicitly known public A_R,b_R and one deterministic public fake s*. The adversary sees the whole statement/relation, context, claim/UTXO, branch, anchors/window, capsule bytes, checking key, auxiliary data, native verification key, masked signature, audit statements and any related capsules. Full-public correlations do **not** save the source because the attacker recovers the actual common root T. Independent nonuniform quantum advice, coherent quantum queries, related-capsule openings or retained malicious coins are unnecessary. Replaying the repaired row structure with different honest native signatures cannot cure the leakage. The proposed release is **not** genuine ordinary QPT-LWE distribution: the structured A,b share relations, and no ordinary-LWE challenge simulator is instantiated. There is NO positive secure witness-KEM construction advance.

**Next exact missing equation:** Find a classical-PPT `Comp(R_original,x)` that instantiates a genuine x-dependent ordinary-QPT-LWE challenge *together* with source opening data, statement, capsule, public CK/Aux, context, native checking key and related capsules, without knowing challenge secret or calling SourceOpen. For **every** `w` with `R_original(x,w)=1`, `Open(Comp(x),w)=T` for the SAME precommitted T. Any arbitrary unauthorized QPT output of T or accepted preauthorized native signature must let a straight-line reduction output a **valid ORIGINAL witness** or independently break a specified QPT-secure assumption, not merely extract a representation volunteered by the adversary. Independently justified generic FALSE and hard-TRUE full-view security, one-honest N-of-N malicious graph/abort, finite DA/censorship, adaptive openings, practical 128-bit quantum security and the *conditional* Bitcoin no-EC-path PQ native endpoint all remain unresolved. Do not disable the automation. No full PR diff, external literature or other repositories were used.
