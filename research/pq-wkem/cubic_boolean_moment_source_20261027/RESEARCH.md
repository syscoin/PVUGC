# Cubic Boolean-moment SOURCE release: exact repair for a restricted false ORIGINAL statement

**2026-10-27, bounded offline research iteration.** Status: a new explicit degree-three SOURCE release eliminates a known degree-two false-key-recovery opening **for the specific unsatisfiable one-variable 3CNF below**. This is a source-dependent, fully simulated restricted construction component, **not a qualified generic-NP/BTC PQ witness-KEM breakthrough**. It does not repair the known ghost/affine attacks against other source families or prove hard-true extraction.

## Exact polynomial SOURCE compiler and honest off-chain release

For arbitrary 3CNF F (repeated literals allowed), form anchor a=z0, variable one-hot pairs X_i^0,X_i^1, and three slack coordinates S_j^1,S_j^2,S_j^3 per clause. Let B_F consist of one equation (sum of each group)-a=0 and one equation per clause: (sum of its three truthmaking variable coordinates)+S_j^1+2S_j^2+3S_j^3-4a=0. Every valid ORIGINAL Boolean assignment W produces a **binary** z(W) with a=1, one choice per group and B_F z(W)=0. Conversely any such binary one-hot z with a=1 gives an ORIGINAL W. Setup does not know W.

Set degree D=3. Public coordinates indexed by multisets I=(i,j,k) with 0<=i<=j<=k<n; N=binom(n+2,3). Construct M_F^(3) by multiplying each linear source equation (B_F z)_r=0 by every homogeneous degree-two monomial z_i z_j, and multiplying each Boolean equation z_i^2-a*z_i=0 (i>0) by every degree-one monomial. Let e select a^3. This is an explicit classical-PPT compiler with O(n^3) coordinates/rows. Honest W opens Y(W)_I=z_i(W)z_j(W)z_k(W), with M Y=0, e^T Y=1. For any valid W, exactly H=binom(h+2,3) entries of Y equal 1, h=1+(number of one-hot groups). Different valid witnesses may have different moment states; no canonical common intermediate is required.

For a k=256-bit seed K and **actual native** KeyGen(K)->(sk,pk), draw U,Z independently uniform {0,1}^k; publish D=U XOR Z, V=K XOR U. Injectively encode a single uniform Z as correlated radix-m digits t_j, m=floor(q/g), ell=ceil(k/log2 m). For each column sample independently u_j uniform F_q^R, epsilon_j i.i.d. ternary, and publish p_j=M^T u_j+epsilon_j+g*t_j*e (mod q). The complete public view is the bound ORIGINAL relation/claim/UTXO/path/branch/anchors/window, capsule, native pk(K), context and allowed auxiliary/related capsules.

Every ORIGINAL W computes Y(W)^T p_j = g*t_j + Y(W)^T epsilon_j. If 2H < min(g, q-(m-1)g), cyclic nearest-codeword decoding recovers every t_j for every noise draw and every valid W, then K=V XOR (D XOR Z). This is the **same precommitted K** across all accepted ORIGINAL W. All witness evidence, polynomial monomial evaluation and decoding remain off chain. This universal correctness property is not generic SOURCE *security*.

## Degree-two failure and degree-three restricted repair

Fix F_false=(x OR x OR x) AND (NOT x OR NOT x OR NOT x), which has no ORIGINAL witness. The explicit degree-two source has 45 coordinates, 53 rows, rank 42 over F_65537. Despite adding all degree-two Boolean constraints, it has a PUBLIC normalized **integer** pseudo-moment Y with M_2 Y=0, e^T Y=1, ||Y||_1=38 (exact coefficients reconstructed and checked in the executable below). At q=65537, g=512, radix 128, ternary errors, |Y^T epsilon|<=38 and 2*38<512, so this false SOURCE recovers every digit and the full precommitted seed without ORIGINAL W. This is not an attack on the independent uniform-B transverse-LWE reference.

The *same false statement* under degree-three lifting has 165 coordinates, 297 rows and **rank 165 over F_65537**. This full column rank implies an efficiently computable c with M_3^T c=e. For each digit t and every epsilon, p_t = M_3^T(u+g*t*c)+epsilon exactly; uniform u -> u+g*t*c is a bijection. Thus the source-dependent false ciphertext is **exactly independent of the digit**, and in fact is full uniform F_q^165 for every epsilon. It has an explicit source-specific straight-line null simulator that needs neither the unknown signing seed, the LWE challenge secret nor a SourceOpen oracle. The separate independent standard-library Python checker verifies an explicit 53-term c and all 37 pointwise real/null couplings, in addition to the exact rank checks embedded here.

For F_true=(x OR NOT x OR x), both x=0 and x=1 are distinct valid ORIGINAL witnesses, producing distinct degree-three Y0 != Y1; N=56, R=93, rank 54, each Y has exactly 10 ones. q=65537, g=512, radix 128, ell=37 satisfy 2H=20<512 and wrap gap q-127*512=513. Both recover the same real 256-bit K in the exact checker. No hard-true witness hardness or extraction follows (this source is intentionally easy).

## Full joint-public and coherent-QPT theorem, scoped precisely

For this *particular* false F and an honestly generated public native checking key pk(K), condition on its native secret K and public context. The false-column distribution is independent of Z and all target masks; after null translation, (U,Z) -> (D,V) is a bijection for every fixed K, so (D,V) is exactly a pair of independent uniform 256-bit strings conditional on K **and its actual pk(K)**. Null columns are independent of (D,V,K), not merely marginally pad-hiding. The full public distribution is therefore *identical* to pk(K) plus independent noise, for arbitrary coherent QPT distinguishers and classical/quantum auxiliary states that can be efficiently simulated from pk and the public statement without target hidden coins. Independently randomized related false-source capsules compose after conditioning on permitted common public information; leaking K through another capsule or exposing the target U/Z is excluded. A native seed-recovery or intended-path forgery in this null view reduces straight-line to a separately assumed QPT-secure native primitive. No particular SLH scheme, practical QPT security estimate or deployed native Bitcoin verification was instantiated or tested.

The theorem **does not** extend to arbitrary false x, to malicious N-of-N setup, arbitrary correlated/selected auxiliary information, native forgery on hard true instances, or standard-QPT LWE for structured M. An all-false exact-row-span compiler plus all-true normalized openings at polynomial cost would allow public Gaussian elimination to decide SAT, as established in the earlier rowshift-decision-bound research. This restricted repair therefore cannot simply be claimed as a generic construction.

## Exact missing security obligations

For one efficient compiler for arbitrary ORIGINAL NP / BTC-SYS PoW, with concrete source-dependent capsules and real checking-key/auxiliary/related-capsule correlations, prove: **(i)** every valid ORIGINAL W recovers the same K, **(ii)** every false x has an independently instantiated coherent-QPT full-public simulator, **(iii)** arbitrary unauthorized hard-true final-key recovery or accepted native forgery implies an ORIGINAL witness or independently justified PQ break without assuming adversary-provided internal representation. No general answer to (ii) or (iii) was obtained here. Generic PoW/cumulative-work best-chain assumptions, SYS header/tag validation, malicious ceremony, challenge graph, timing/DA and conditional Bitcoin PQ endpoint also remain unresolved.

## Exact executed self-contained checker and results

The JavaScript function below was executed in this turn; its source is included verbatim, and the JSON directly below is its actual returned value. A separate standard-library local Python implementation (checker SHA256 ddd6aeba4573880c2a28444ccaac7b1e54f6e63b1b163b5fd48544e9ca2db5fd) ran twice, 281 exact assertions each with byte-identical stdout SHA256 da75a7c9010e5270c4099d54d61730a00941118b2cf0787e7b940561368df9ef; it additionally constructed the complete row-shift certificate and checked all 37 pointwise couplings. These finite checks are not quantum attack experiments or native SLH implementations.

~~~javascript
console.log(JSON.stringify((function executedChecker(){
 const q=65537,g=512,radix=128;let checks=0;
 const ok=(v,s)=>{if(!v)throw Error(s);checks++},mod=x=>(x%q+q)%q,dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
 function combo(n,d){let o=[];function go(a,k){if(a.length===d){o.push([...a]);return}for(let i=k;i<n;i++){a.push(i);go(a,i);a.pop()}}go([],0);return o}
 function source(F){let groups=[[1,2]],n=3;for(const f of F){groups.push([n,n+1,n+2]);n+=3}
 let rows=[];for(const G of groups){let a=Array(n).fill(0);a[0]=-1;for(const i of G)a[i]=1;rows.push(a)}
 for(let j=0;j<F.length;j++){let a=Array(n).fill(0);a[0]=-4;for(const b of F[j])a[groups[0][b]]++;for(let k=0;k<3;k++)a[groups[j+1][k]]=k+1;rows.push(a)}
 return {F,groups,n,rows}}
 function lift(S,d){let mon=combo(S.n,d),loc=new Map(mon.map((a,i)=>[a.join(','),i])),rows=[];const ix=a=>loc.get([...a].sort((x,y)=>x-y).join(','));
 for(const r of S.rows)for(const p of combo(S.n,d-1)){let a=Array(mon.length).fill(0);for(let i=0;i<S.n;i++)if(r[i])a[ix([...p,i])]+=r[i];rows.push(a)}
 for(let i=1;i<S.n;i++)for(const p of combo(S.n,d-2)){let a=Array(mon.length).fill(0);a[ix([...p,i,i])]++;a[ix([...p,0,i])]--;rows.push(a)}
 let e=Array(mon.length).fill(0);e[ix(Array(d).fill(0))]=1;return {mon,rows,e}}
 function rank(R,n){let piv=new Map();for(const raw of R){let a=raw.map(mod);for(const j of [...piv.keys()].sort((x,y)=>x-y)){let k=a[j];if(k)for(let z=0;z<n;z++)a[z]=mod(a[z]-k*piv.get(j)[z])}let j=a.findIndex(x=>x!==0);if(j<0)continue;let inv=1,b=a[j],e=q-2;while(e){if(e&1)inv=mod(inv*b);b=mod(b*b);e=Math.floor(e/2)}piv.set(j,a.map(x=>mod(x*inv)))}return piv.size}
 function witness(S,b){let z=Array(S.n).fill(0);z[0]=z[S.groups[0][b]]=1;for(let j=0;j<S.F.length;j++){let t=S.F[j].filter(x=>x===b).length;if(!t)return null;z[S.groups[j+1][3-t]]=1}return z}
 const Ffalse=source([[1,1,1],[0,0,0]]),Ftrue=source([[1,0,1]]);
 ok(!witness(Ffalse,0)&&!witness(Ffalse,1),"false ORIGINAL");
 const A2=lift(Ffalse,2),A3=lift(Ffalse,3),T3=lift(Ftrue,3);
 const r2=rank(A2.rows,A2.mon.length),r3=rank(A3.rows,A3.mon.length),rt=rank(T3.rows,T3.mon.length);
 ok(A2.mon.length===45&&A2.rows.length===53&&r2===42&&rank([...A2.rows,A2.e],45)===43,"D2 source");
 ok(A3.mon.length===165&&A3.rows.length===297&&r3===165&&rank([...A3.rows,A3.e],165)===165,"D3 false FULL row span");
 ok(T3.mon.length===56&&T3.rows.length===93&&rt===54&&rank([...T3.rows,T3.e],56)===55,"D3 true");
 const coeff=[[0,0,1],[0,2,1],[0,3,1],[0,6,1],[0,7,-3],[0,8,3],[1,6,1],[1,7,-2],[1,8,1],[2,2,1],[2,3,1],[2,7,-1],[2,8,2],[3,3,1],[3,6,-1],[3,7,1],[3,8,1],[4,6,1],[4,7,-2],[4,8,1],[5,6,1],[5,7,-2],[5,8,1],[6,6,1],[7,7,-3],[8,8,3]];
 const table=new Map(coeff.map(([i,j,x])=>[i+','+j,x])),ghost=A2.mon.map(m=>table.get(m.join(','))||0);
 ok(dot(ghost,A2.e)===1&&ghost.reduce((s,x)=>s+Math.abs(x),0)===38,"ghost anchor and L1");
 for(const r of A2.rows)ok(dot(ghost,r)===0,"ghost moment row");
 const W=[witness(Ftrue,0),witness(Ftrue,1)],YY=W.map(w=>T3.mon.map(m=>m.reduce((a,i)=>a*w[i],1)));
 ok(YY[0].join()!=YY[1].join(),"different W states");
 for(const y of YY){ok(dot(y,T3.e)===1&&dot(y,y)===10,"honest moment");for(const r of T3.rows)ok(dot(r,y)===0,"honest row")}
 const state={v:0x270acbd},rnd=()=>{state.v=(Math.imul(state.v,1664525)+1013904223)>>>0;return state.v};
 const next256=()=>{let a=0n;for(let i=0;i<8;i++)a=(a<<32n)|BigInt(rnd());return a};
 let K=next256(),U=next256(),Z=next256(),D=U^Z,V=K^U,ds=[],x=Z;
 for(let j=0;j<37;j++){ds.push(Number(x%128n));x/=128n}ok(x===0n,"radix");
 const col=(M,u,err,t,e)=>{let p=err.map((a,i)=>mod(a+g*t*e[i]));for(let j=0;j<M.length;j++)if(u[j])for(let i=0;i<p.length;i++)if(M[j][i])p[i]=mod(p[i]+u[j]*M[j][i]);return p};
 const decode=y=>{let best=-1,d=q;for(let j=0;j<radix;j++){let a=mod(y-j*g),dist=Math.min(a,q-a);if(dist<d){best=j;d=dist}else if(dist===d){best=-1}}ok(best>=0,"ambiguous");return best};
 let digits=[[],[]],bad=[];
 for(const t of ds){
  let u=T3.rows.map(()=>rnd()%q),err=T3.mon.map(()=>rnd()%3-1),p=col(T3.rows,u,err,t,T3.e);
  YY.forEach((y,i)=>{let v=decode(mod(dot(y,p)));ok(v===t,"true opening");digits[i].push(v)});
  u=A2.rows.map(()=>rnd()%q);err=A2.mon.map(()=>rnd()%3-1);p=col(A2.rows,u,err,t,A2.e);
  let v=decode(mod(dot(ghost,p)));ok(v===t,"false quadratic recovery");bad.push(v)
 }
 const fromRad=a=>a.reduceRight((z,j)=>z*128n+BigInt(j),0n);
 for(const a of [...digits,bad])ok((V^(D^fromRad(a)))===K,"same precommitted K");
 ok(2*10<g&&2*38<g&&q-(radix-1)*g>2*10,"noise bounds");
 return {record:"cubic_boolean_moment_source_20261027",status:"restricted false SOURCE repair only; no generic-NP WKEM",falseD2:{coordinates:45,rows:53,rank:r2,shortGhostL1:38,actualFalseSeedRecovery:true},falseD3:{coordinates:165,rows:297,rank:r3,shiftInRowSpan:true},trueD3:{coordinates:56,rows:93,rank:rt,distinctOriginalWitnesses:2,activeMomentCoordinates:10,samePrecommittedSeed:true},parameters:{q,g,radix,columns:37},assertions:checks};
})(),null,2));
~~~

~~~json
{
  "record": "cubic_boolean_moment_source_20261027",
  "status": "restricted false SOURCE repair only; no generic-NP WKEM",
  "falseD2": {
    "coordinates": 45,
    "rows": 53,
    "rank": 42,
    "shortGhostL1": 38,
    "actualFalseSeedRecovery": true
  },
  "falseD3": {
    "coordinates": 165,
    "rows": 297,
    "rank": 165,
    "shiftInRowSpan": true
  },
  "trueD3": {
    "coordinates": 56,
    "rows": 93,
    "rank": 54,
    "distinctOriginalWitnesses": 2,
    "activeMomentCoordinates": 10,
    "samePrecommittedSeed": true
  },
  "parameters": {
    "q": 65537,
    "g": 512,
    "radix": 128,
    "columns": 37
  },
  "assertions": 474
}
~~~

## Provenance

Connected `syscoin/PVUGC` draft/open/unmerged PR #1, branch `research/pq-wkem-validation-20260918`, starting head `0aa36f63bdbb83295a19156e25731e40b3f41bd9`. Latest substantive issue comment read: 6455605186. Exact predecessor blob reads: onehot norm-rigidity d33d3fd136b793a3e429dde9de656aa39dbf3433 and anchored Fourier-null e55dd86125ce5f9371ea52fa2a30882a931becc1. Only offline arithmetic and authorized connected GitHub reads/publication; no external search/literature, production code, workflow, merge, review, or deployment. No independent agent invoked.
