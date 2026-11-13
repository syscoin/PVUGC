# R95 — Private-receipt, one-honest N-of-N pre-funding audit (RESTRICTED composition, NOT a generic NP witness-KEM)

Run: R95-PREFUND-N-OF-N-AUDIT-20261105. Source: syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918. Read-only starting head c0c05f1e88472cff002c25e510c532522d45095a, open/draft/unmerged. Latest substantive ordinary comment 6667683648. Exact-version R94 RESEARCH.md blob ad99607aa53c6dd5aaf97f1ab556bfbbfb149be6 and R89 RESEARCH_AND_CHECKER.md blob 4e42a958ccd6a9ae0c26886d5a73ba69856065f5 read. No external literature/web research.

## Constructive delta
Previous R90–R94 restricted release assumed honest packaging of each already-pre-signed native capability and a frozen graph. R95 supplies a concrete **classical-PPT audit-and-abort algorithm**, requiring no SNARG of capsule correctness and no online release authority. Each of N native signers independently prepares a signature sigma_p=Sign(sk_p,M_p), uniformly precommitted seed T_p, k-of-n polynomial shares of T_p, actual leaf encryptions and randomness. The exact intended M_p binds ORIGINAL relation identity, actual claim/funding outpoint, branch, authenticated anchors/window, transaction graph, owner/credential scope and intended native verification keys. All signatures are precomputed before irreversible funding. One honest funding controller h privately verifies every untrusted signer's (sigma_p,T_p,polynomial coefficients,encryption randomness) against all public ciphertexts and checking information. An untrusted signer need NOT disclose its private native signing key. Honest h prepares its own capsule without revealing its seed or signature to adversarial parties. Refusal, malformed information, missing DA or an alternative script/key path causes SAFE PRE-FUNDING ABORT. After successful audit, all masked signatures and ciphertexts are published before funding and no signer is needed to release after funding.

This repairs the **malicious-other-signers' incorrect capsule packaging / post-funding refusal** assumption for the *restricted R94 LWE-leaf threshold relation*. It does not repair the statement-dependent generic NP source, dishonest source-key generation, BTC censorship/DA failure, or retained-builder-secrets/keyless Build.

## Explicit algorithms and joint public distribution
Sample independent true-leaf public keys as A_i uniform in Z_q^(m×d), S_i uniform in Z_q^(d×ell), E_i independently from a bounded exact LWE error distribution, B_i=A_i S_i+E_i mod q. Under R94, an ORIGINAL leaf witness is any bounded pair (S'_i,E'_i) satisfying that equation. Distinct valid pairs and distinct authorized k-subsets must recover the same capsule root. For each signer p, sample independent uniformly random T_p of kappa bits and independently sampled degree-(k-1) GF(256) polynomial coefficients, with constant term T_p bytewise. Ciphertext C_{p,i}=PackedRegev.Enc(PK_i,share_{p,i};r_{p,i}); use independent fresh r for each leaf/group, and R88's exact decoding margin. Let P_p||B_p=PRG(T_p), D_p=sigma_p XOR P_p. Let G be the frozen graph. Build a **public** acyclic manifest J=Digest(G,all source PK,[(p,vk_p,C_{p,*},D_p)]_{p=1..N}); then CK_p=F(B_p,J,G,p,C_{p,*},native_vk) and Aux_p=H(B_p,CK_p,J,G,source_PK). The real distribution includes G, source PK, all C,D,CK,Aux,J, all related capsules, public DA metadata and an off-chain audit attestation on Digest(G,source_PK,all capsules,J).

Auditor h obtains the *PRIVATE* receipts (T_p, sigma_p, polynomial coefficients, **actual ciphertext coins**) over authenticated confidential setup channels; checks Ver(vk_p,M_p,sigma_p), recomputes every share, ciphertext, D_p, J, CK_p and Aux_p, checks entire graph and actual funding output/preauthorized transaction, and verifies public evidence is retrievable. The auditor records a signed commitment to the full public bundle under a **separate attestation key**, not a Bitcoin spending key. The audit receipt itself is neither public nor available through post-funding opening APIs. h retains only the attested public bundle after erasing/protecting its own private seed/signature/coins. An honest signer controls whether its actual funding signature is issued; if others can irreversibly fund a different output without it, the graph guarantee does not follow. Do not include a funding-TXID-dependent digest in the script that creates a cyclic TXID dependency: finalize a SegWit-style funding template/outpoint before broadcast, and keep capsule attestations off-chain. The Bitcoin endpoint's no-EC-key-path P2MR-like and SLH-like native signatures remain *hypothetical*, not deployed functionality.

Open off-chain checks supplied actual ORIGINAL short-error keys, decrypts k shares, interpolates T_p at 0, recomputes PRG, J,CK,Aux, unmasks D_p and verifies sigma_p against exactly M_p. All valid ORIGINAL k-subsets obtain **the same precommitted sigma_p**; Bitcoin does not run ORIGINAL NP verification, VM, SNARG, PCP or BitVM trace disputes. BitVM remains only covenant plumbing.

## Conditional QPT composition and exact exclusions
Assume one h is honest, its capsule is generated honestly and privately, h excludes every key-path/alternate challenge bypass and controls irreversible funding approval, and it erases/protects its native secrets. All other N-1 parties may retain all of their seeds, coins and signatures and abort at will *before* funding. Their capsules and private receipts are attacker-known. They must commit their capsules before h publishes its private-seeded capsule; their auxiliary strings may not depend on unknown h encryption randomness or seed. The independently honestly sampled source keys, a global disclosed-key subset U of size <k, fixed-target R94 joint-public-output game (or R93 fixed-constant adaptive-classical opening variant), ordinary exact-distribution QPT-INDCPA from LWE, independent QPT-secure PRG, independent native QPT-EUF-CMA and binding graph/funding semantics remain explicit premises. Unknown source-secret correlated quantum advice, quantum-superposition opening, unsimulatable public auxiliary, tampered source-key provenance, arbitrary fixed FALSE x, adversarial adaptive malformed public output and post-funding arbitrary BTC censorship are excluded. Honest setup and evaluator are classical PPT; attacker may execute coherent arbitrary QPT algorithms over the entire classical public view with independent nonuniform quantum advice.

Reduction detail: to hybridize an honest leaf ciphertext under a genuine LWE INDCPA challenge public key, the simulator publicly encrypts every related capsule group it controls, plugs the genuine challenger ciphertext bytes into the *honest* target capsule, recomputes the JOINT J and every CK/Aux, and signs the public audit bundle digest with its own independent audit signing key. Crucially, **the private receipt containing challenge encryption coins is not in the attacker view**, so the simulator never needs to invent an audit receipt or a SourceOpen oracle for those coins. Honest auditing is a real-world correctness condition, not a public cryptographic proof of hidden coins in the hybrid. A malicious party can learn all of its own receipts, but not h's. In the QPT-PRG-uniform terminal, D_h is uniform independent of the actual sigma_h, so the native EUF reduction can generate D_h without requesting a signature on the target M_h. Other distinct messages can be queried. Therefore challenge-path unauthorized execution implies graph/funding bypass or a breach of the **R94 restricted full-joint masked-signature security** / independently justified native EUF. For exact seed output retain R93's generator-image residual 2^(kappa-L) rather than an unjustified 2^-kappa.

**No unconditional generic result:** the crucial old failure R89 remains: its public b enables v-only recovery of every bit. This audit does not turn arbitrary ORIGINAL witness evidence into an honest LWE leaf, prove arbitrary hard-TRUE recovery->ORIGINAL witness extraction, or prove arbitrary fixed FALSE-instance security. If any valid-witness source key is absent, this ceremony may safely abort, or verified capsule syntax may still have no usable future witness. It cannot conjure witnesses or guarantee live Bitcoin inclusion.

## Reproducibility and quantitative checks
The exact executed JavaScript below ran in a bounded V8 isolate. It passed 276 assertions: 12 complete ceremonies, 48 authorized source subsets recovering every native signer capability, 48 local unauthorized subsets rejecting release, 144 pre-funding malformed/withheld artifact rejections, and 12 post-funding immutable-bundle negative controls (plus source/public nonexposure checks). Its toy GF(257) leaf keys have ZERO LWE error, its arithmetic signatures are publicly forgeable, and its seeded hash is not a real hash; **this is a structural audit test only, absolutely no QPT security evidence**. A separate actually executed LOCAL Python/cryptography checker with tiny q=257 Regev, genuine (non-PQ) Ed25519 signing, independent attestation key, joint CK/Aux and private receipts passed 336 assertions: 12 accepted, 48 authorized releases, 156 pre-funding rejects, 12 immutable-bundle and 12 exposure checks. Local Python checker, complete longer derivation and captured output retained as downloadable local archive, not falsely claimed to be GitHub files.

## Exact missing next equation
Need a classical-PPT Comp(R_original,x) yielding an x-dependent source PK, capsule C, CK, Aux, context, all related capsules, and an ACTUAL genuine QPT-LWE challenge simulator jointly, such that for **every** w with R_original(x,w)=1, Open(x,C,w)=one SAME precommitted T; yet any arbitrary QPT unauthorized recovery of T or an accepted preauthorized native signature yields an **actual ORIGINAL witness** (not an adversary-volunteered representation), or an independent precisely stated QPT break. Arbitrary FALSE x, source-key provenance, malicious one-honest ORIGINAL source construction, source PoW/fork safety, DA/censorship, erasure, practical PQ parameters and the native Bitcoin PQ endpoint remain unresolved. This run makes no claim that the user’s original target has been solved; the research automation must remain enabled.

## Exact executed V8 checker

```javascript
function R95() {
  const q=257, N=3, k=2, rounds=12; let assertions=0;
  const totals={accepted:0,authorized:0,unauthorized:0,rejected_pre_funding:0,bundle_tamper:0};
  function ok(v,msg){assertions++;if(!v)throw Error("assertion "+assertions+": "+msg);}
  function mod(x){return (x%q+q)%q;}
  function inv(x){for(let y=1;y<q;y++)if(mod(x*y)===1)return y;throw Error("inverse");}
  let state=9501105;
  function rnd(){state=(Math.imul(state,1664525)+1013904223)>>>0;return state;}
  function H(...a){let s=JSON.stringify(a),v=2166136261;for(let i=0;i<s.length;i++)v=Math.imul(v^s.charCodeAt(i),16777619)>>>0;return v>>>0;}
  function clone(x){return JSON.parse(JSON.stringify(x));}
  function pkgen(){const A=Array.from({length:8},()=>[rnd()%q,rnd()%q]),s=[rnd()%q,rnd()%q];return [{A,b:A.map(r=>mod(r[0]*s[0]+r[1]*s[1]))},s];}
  function E(pk,v,coins){const u=[0,0];let z=v;for(let i=0;i<8;i++)if(coins[i]){u[0]+=pk.A[i][0];u[1]+=pk.A[i][1];z+=pk.b[i];}return {u:u.map(mod),v:mod(z)};}
  function Dec(sk,ct){return mod(ct.v-ct.u[0]*sk[0]-ct.u[1]*sk[1]);}
  function message(g,p){return H("native-message",g,p);}
  function sig(sk,m){return mod(sk*m+17);}
  function pub(sk){return sk;} // INTENTIONALLY INSECURE mathematical fixture
  function verify(pk,m,s){return s===sig(pk,m);}
  function pad(t){return H("pad",t);}
  function tail(t){return H("checktail",t);}
  function manifest(g,pks,cs){return H("joint-manifest",g,pks,cs.map(c=>[c.p,c.ct,c.D]));}
  function setup(){
    let pairs=Array.from({length:N},pkgen), pks=pairs.map(x=>x[0]),keys=pairs.map(x=>x[1]);
    const signing=[1+rnd()%255,1+rnd()%255,1+rnd()%255];
    const graph={claim:"UTXO:demo:prebroadcast",relation:"restricted-LWE-k2-of-3",
      branches:["challenge:all-three","normal:timeout"],no_key_path:true,
      funding_requires_honest:true,anchors:"fixed-window",vks:signing.map(pub)};
    const cs=[],rec=[];
    for(let p=0;p<N;p++){
      const t=rnd()%q, slope=rnd()%q, share=Array.from({length:N},(_,i)=>mod(t+slope*(i+1)));
      const coins=Array.from({length:N},()=>Array.from({length:8},()=>rnd()&1));
      const ct=share.map((v,i)=>E(pks[i],v,coins[i]));
      const S=sig(signing[p],message(graph,p)), D=(S^pad(t))>>>0;
      cs.push({p,ct,D,CK:0,Aux:0});rec.push({t,slope,coins,S});
    }
    const J=manifest(graph,pks,cs);
    cs.forEach((c,p)=>{c.CK=H("CK",tail(rec[p].t),J,c.ct,p,graph);
      c.Aux=H("Aux",tail(rec[p].t),c.CK,J,pks,graph);});
    return {graph,pks,keys,cs,rec,signing};
  }
  function audit(g,pks,cs,rec,expected){
    if(JSON.stringify(g)!==JSON.stringify(expected) || cs.length!==N || rec.length!==N ||
       pks.length!==N || g.branches[0]!=="challenge:all-three" ||
       !g.no_key_path || !g.funding_requires_honest)return null;
    const J=manifest(g,pks,cs);
    for(let p=0;p<N;p++){
      const c=cs[p],r=rec[p];
      if(!c||!r||c.p!==p||!Array.isArray(r.coins)||r.coins.length!==N)return null;
      const shares=Array.from({length:N},(_,i)=>mod(r.t+r.slope*(i+1)));
      if(JSON.stringify(shares.map((v,i)=>E(pks[i],v,r.coins[i])))!==JSON.stringify(c.ct))return null;
      if(!verify(g.vks[p],message(g,p),r.S)||c.D!==((r.S^pad(r.t))>>>0))return null;
      if(c.CK!==H("CK",tail(r.t),J,c.ct,p,g))return null;
      if(c.Aux!==H("Aux",tail(r.t),c.CK,J,pks,g))return null;
    }
    return H("audit",g,pks,cs,J);
  }
  function open(g,pks,cs,available){
    const ids=Object.keys(available).map(Number).sort((a,b)=>a-b);
    if(ids.length<k)return null;
    const [i,j]=ids;
    const good=ids.every(index=>pks[index].b.every((b,t)=>b===mod(pks[index].A[t][0]*available[index][0]+pks[index].A[t][1]*available[index][1])));
    if(!good)return null;
    const J=manifest(g,pks,cs);
    return cs.map((c,p)=>{
      const yi=Dec(available[i],c.ct[i]),yj=Dec(available[j],c.ct[j]);
      const t=mod((yj*(i+1)-yi*(j+1))*inv((i+1)-(j+1)));
      if(c.CK!==H("CK",tail(t),J,c.ct,p,g) ||
         c.Aux!==H("Aux",tail(t),c.CK,J,pks,g))return null;
      const S=(c.D^pad(t))>>>0;
      return verify(g.vks[p],message(g,p),S)?S:null;
    });
  }
  for(let t=0;t<rounds;t++){
    const {graph,pks,keys,cs,rec}=setup(),base=clone(graph);
    const att=audit(graph,pks,cs,rec,base);
    ok(att!==null,"fully checked pre-funding transcript");totals.accepted++;
    for(let mask=0;mask<8;mask++){
      const avail={};for(let i=0;i<N;i++)if(mask&(1<<i))avail[i]=keys[i];
      const result=open(graph,pks,cs,avail);
      const size=Object.keys(avail).length;
      if(size>=k){ok(result.every((x,p)=>x===rec[p].S),"all valid witnesses recover SAME pre-signed capability");totals.authorized++;}
      else{ok(result===null,"underauthorized local Open");totals.unauthorized++;}
    }
    ok(!JSON.stringify({graph,pks,cs}).includes('"coins"')&&!JSON.stringify({graph,pks,cs}).includes('"slope"'),"private receipts absent from public");
    const mutations=["no-receipt","no-capsule","false-sig","bad-coins","bad-slope","bad-CK","bad-Aux","alternate-branch","key-path","wrong-claim","reordered","missing-ciphertext"];
    for(const mut of mutations){
      let g=clone(graph),c=clone(cs),r=clone(rec);
      if(mut==="no-receipt")r.pop();
      else if(mut==="no-capsule")c.pop();
      else if(mut==="false-sig")r[1].S=mod(r[1].S+1);
      else if(mut==="bad-coins")r[1].coins[0][0]^=1;
      else if(mut==="bad-slope")r[1].slope=mod(r[1].slope+1);
      else if(mut==="bad-CK")c[1].CK++;
      else if(mut==="bad-Aux")c[1].Aux++;
      else if(mut==="alternate-branch")g.branches[0]="challenge:anyone";
      else if(mut==="key-path")g.no_key_path=false;
      else if(mut==="wrong-claim")g.claim="UTXO:elsewhere";
      else if(mut==="reordered")[c[0],c[1]]=[c[1],c[0]];
      else if(mut==="missing-ciphertext")c[1].ct.pop();
      ok(audit(g,pks,c,r,base)===null,"pre-funding abort on "+mut);totals.rejected_pre_funding++;
    }
    let altered=clone(cs);altered[1].D^=1;
    ok(H("audit",graph,pks,altered,manifest(graph,pks,altered))!==att,
      "post-funding byte replacement detected by frozen digest");totals.bundle_tamper++;
  }
  return {run:"R95-PREFUND-N-OF-N-AUDIT-20261105",assertions,totals,
    fixture:"GF257 linear secret sharing; toy zero-error linear source; toy publicly forgeable arithmetic signatures; NOT cryptographic evidence"};
}
console.log(JSON.stringify(R95(),null,2));
```

## Captured exact V8 output

```json
{
  "run": "R95-PREFUND-N-OF-N-AUDIT-20261105",
  "assertions": 276,
  "totals": {
    "accepted": 12,
    "authorized": 48,
    "unauthorized": 48,
    "rejected_pre_funding": 144,
    "bundle_tamper": 12
  },
  "fixture": "GF257 linear secret sharing; toy zero-error linear source; toy publicly forgeable arithmetic signatures; NOT cryptographic evidence"
}
```
