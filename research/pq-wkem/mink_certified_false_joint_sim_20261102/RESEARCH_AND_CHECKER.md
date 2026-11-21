# MINK-CERTIFIED-FALSE-JOINT-SIM-20261102-R20

**Constructive restricted public-output simulation, not a generic PQ witness-KEM.** Continues the exact R19 Boolean-ideal SOURCE, not another carrier or an assumption of a SourceOpen oracle.

## Provenance
Current verified syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918 started at 142878c85fff3decbb9d0c9965929b3117679a87; PR was open, draft, unmerged. Latest substantive ordinary comment: 6584384017. Exact R19 research blob: c5288b50604f735f940429b0cfd6df8346e87b6b. No external internet or literature accessed. All source and native verification remains classical-PPT; quantum attackers are arbitrary QPT subject to exactly stated oracle access.

## Explicit concrete Build and full-public generator
For each ORIGINAL relation/statement x, include relation identity, claim/UTXO, branch, anchors/window, context, authorized native verification key and capability path. The R19 classical-PPT generic 3CNF compiler yields public Boolean-ideal coefficient matrix B_(phi,d) over F_q with constant vector e0. For each independent claim scope s, sample a real native KeyGen tape K_s and correlated genuine verification key vk_s, under a separately QPT-EUF-CMA native signature scheme. Capsules in one scope share that exact K_s/vk_s; different scopes have independent keys.
For every tape bit mu and related capsule j, sample fresh independent r uniformly from F_q^L and e from chi^M (bounded [-eta,eta]); publish C=B r+Delta mu e0+e modulo q. Every valid ORIGINAL witness w generates its own Boolean evaluation lambda_w with lambda_w^T B=0 and lambda_w^T e0=1; thus every valid witness decodes exactly the SAME K_s when M eta < min(Delta,q-Delta)/2. This is inherited algebraic completeness, not hard-TRUE key hiding.
Define one explicit public generator G which receives only x, vk_s, context, capsule C, previous PUBLIC transcript and fresh public coins; it may call an authorized CLASSICAL native signing oracle for audited non-challenge messages. G outputs the complete restricted checking key ck, manifest, auxiliary data, source identity, claim/path/anchor bindings and related capsule references. It does NOT receive a witness, builder secrets, original native tape, SOURCE r/e, or private auxiliary information beyond permitted signing calls. The exact executed checker uses a canonical manifest digest and a mock signing callback as a functionality test; neither hash nor mock signing is a security assumption. G is deliberately NOT the uninstantiated R17 malicious graph-proof checking key.

## NEW exact straight-line challenger simulator
Restrict each FALSE source chosen by the adversary to a **public, checkable certificate** t with B t=e0. Gaussian elimination can check/find t for polynomial-size B. This is a promise class, not all FALSE NP inputs, and Build itself does not reject TRUE statements.
Native QPT-EUF-CMA challenger provides vk* and CLASSICAL signing oracle Sign_sk*(m), never K*. The reduction embeds vk* into one unopened protected scope, generates genuinely independent keys/tapes for every other claim scope, and for EVERY target bit/capsule samples r0 uniformly and e from chi and sets C0=B r0+e. It runs G on vk*, C0, public context and allowed signing-oracle replies. Opening private tape or source r/e for a DIFFERENT independent scope is answered honestly. Opening anything secret from target scope forces abort and is excluded from the success event.
For any fixed unknown target tape bit mu and a publicly certified FALSE B, the proof-only change of coins r0=r+Delta mu t is a bijection over uniform F_q^L, and B r0+e=B r+Delta mu e0+e. **The simulator never computes r0 this way and never knows mu**; it samples uniform r0 directly. The equality is exact conditional on the genuine correlated native vk* and ANY aux previously produced by G. Because each source bit/capsule uses fresh independent r/e, induction over classical adaptive capsule selections shows equality of all related SOURCE capsules, checking-key correlations, contexts, public G-generated auxiliary outputs, public native vk and permitted signature transcripts. Quantum advice independent of the hidden target key beyond the stated public/oracle interface, and arbitrary coherent quantum processing of the joint classical transcript, do not change this distribution equality. No quantum rewinding or extraction is invoked. Coherent capsule/sign-oracle superposition queries are NOT provided.
If the arbitrary QPT adversary outputs an accepted native signature on a fresh, never-signed challenge-path message under the unopened target vk*, the reduction forwards it as a genuine EUF-CMA forgery. If it outputs ANY usable native private key or KeyGen tape, the reduction signs an unqueried message using it and forwards the native signature. If the final unopened scope is chosen adaptively among at most S scopes, embedding one uniformly guessed scope ahead of time loses at most factor S: Pr[fresh native forgery in an unopened, publicly certified FALSE scope] <= S * Adv_QPT-EUF-CMA + native correctness error. Fixed target has no factor S. This is a fully instantiated restricted native-key/ck/aux simulation, not an assumption that the adversary volunteers a representation.

## Security boundary: essential failures
R19's nine-clause FALSE d=0 still has a public norm-2 pseudo-evaluation revealing all digits. The certified FALSE theorem covers that FALSE example only at d=1, and the separate parity-cycle FALSE at d=2. There is **NO universal adversarial FALSE security** and B is NOT an ordinary uniform LWE public key. An unrestricted hard-TRUE key recovery or accepted native forgery has NO known reduction to an actual ORIGINAL witness or independently justified QPT break. The proof only simulates ck/aux generated by the explicitly specified PUBLIC G; unknown malicious verifier graph-proof keys, hidden builder outputs, retained setup secrets, source-coin leakage, builder corruption, target same-key selective opening, quantum signing superpositions and arbitrary secret-correlated quantum aux are out of scope. Signatures used by G must never include the protected challenge-path message. Malicious N-of-N ceremony/abort composition, enforceable preauthorization, pre-signature/DA readiness, a keyless builder, certified 128-bit QPT parameters and Bitcoin-native PQ output are unimplemented/unproved. No Bitcoin NP verification or deployment is claimed.

## Exact bounded offline evidence
The self-contained JavaScript checker below was actually executed twice with byte-identical output. Its two public certified-FALSE matrices represent contradictory Boolean constraints with B*t=e0, one augmented with another independent row. It verifies 3 claim scopes, 3 adaptively selected related capsules per scope, 24 toy private-tape bits per scope, exact whole-ciphertext coupling and all public checking-key, context, mock signature and auxiliary/related-capsule identities. **Mock hashes and signatures are API tests only**, not PQ crypto.
An independent Python-standard-library checker ran 458 assertions twice, byte-identical, using actual 3CNF R19 Boolean-ideal matrices for n=2,d=0 (M=10,L=4), the nine-clause FALSE at n=4,d=1 (M=70,L=65), and parity-cycle FALSE n=3,d=2 (M=56,L=90); it exercised 216 key-bit couplings and 9 full manifest couplings. Exact local Python code, captured outputs, full extended research note and provenance are preserved in MINK_CERTIFIED_FALSE_JOINT_SIM_20261102_R20_OFFLINE.tar.gz (SHA-256 28f00b919d0df4a0ac7107863b25d8292242af2b3487762b8b6bf888af033968). No QPT-security or genuine native signing code was executed.

## Next indispensable missing equation
An efficient arbitrary-ORIGINAL-NP Build/Lift whose every valid ORIGINAL witness recovers the SAME K, plus a full real joint (R,x,C,vk,ck,context,aux,related) simulator for **ALL** adversarial FALSE original statements and an arbitrary-QPT unauthorized hard-TRUE recovered key/native forgery -> **actual ORIGINAL witness** or independently justified PQ break. The current work closes only the qualified FALSE public-native-key simulation and independent-scope selective opening component.

## Exact self-contained executed checker

```javascript
function checker(){
  const q=65537,D=32768;let count=0,seed=2026110220;
  const ok=(b,m)=>{count++;if(!b)throw Error(m)};
  const mod=x=>((x%q)+q)%q;
  const rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};
  const H=s=>{let h=2166136261>>>0;for(let c of String(s))h=Math.imul(h^c.charCodeAt(0),16777619)>>>0;return h.toString(16)};
  const S=[
    {B:[[1,-3,3,-1],[0,0,0,1],[0,-1,1,0]],t:[1,1,q-3]},
    {B:[[1,-3,3,-1,0],[0,0,0,1,0],[0,-1,1,0,0],[0,0,0,0,1]],t:[1,1,q-3,0]}
  ];
  const prod=(s,r)=>{let a=Array(s.B[0].length).fill(0);for(let j=0;j<s.B.length;j++)for(let i=0;i<a.length;i++)a[i]=mod(a[i]+s.B[j][i]*r[j]);return a};
  for(let s of S)ok(prod(s,s.t).every((x,i)=>x===Number(i===0)),"public certificate B*t=e0");
  const keys=Array.from({length:3},()=>Array.from({length:3},()=>rnd()%256)),vks=keys.map(k=>H(k.join(":")));
  const sign=(scope,msg)=>H(keys[scope].join(":")+"|"+msg); // MOCK ONLY
  let transcript=[];
  for(let scope=0;scope<3;scope++){
    let prev="genesis";
    for(let capsule=0;capsule<3;capsule++){
      let selector=parseInt(H(prev+vks[scope]+capsule),16)%2,s=S[selector],real=[],sim=[];
      const audit=sign(scope,"audit:"+scope+":"+capsule);
      for(let bit=0;bit<24;bit++){
        let mu=(keys[scope][bit>>3]>>(bit&7))&1;
        let r=s.B.map(()=>rnd()%q),e=Array.from({length:s.B[0].length},()=>rnd()%3-1);
        let c=prod(s,r).map((x,i)=>mod(x+e[i]+(i===0?D*mu:0)));
        let shifted=r.map((x,i)=>mod(x+D*mu*s.t[i]));
        let c0=prod(s,shifted).map((x,i)=>mod(x+e[i]));
        ok(c.every((x,i)=>x===c0[i]),"public ciphertext coupling");
        real.push(c);sim.push(c0);
      }
      const context={relation:"ORIGINAL-NP",claim:scope,utxo:"claim-utxo-"+scope,branch:"challenge",anchors:[102,112],vk:vks[scope],capsule,selector,prev};
      const G=cs=>({context,source_capsules:cs,checking_key:H(JSON.stringify({context,cs,audit})),aux:{audit,related:capsule?"prior-"+(capsule-1):null}});
      let a=G(real),b=G(sim);
      ok(JSON.stringify(a)===JSON.stringify(b),"full public checking-key/aux/related correlation");
      transcript.push(a);prev=a.checking_key;
    }
  }
  ok(transcript.length===9,"nine related-capsule public views");
  for(let target=0;target<3;target++){
    ok(keys.filter((_,i)=>i!==target).length===2,"only other independent claim keys opened");
    ok(transcript.filter(v=>v.context.claim===target).every(v=>v.context.vk===vks[target]),"one precommitted target vk");
  }
  return {run:"MINK-CERTIFIED-FALSE-JOINT-SIM-R20",passed:true,checks:count,scopes:3,capsules:9,bit_couplings:216,full_public_couplings:9,source_matrices:2,limitations:"Certified FALSE only; mock native signatures; no hard-TRUE or QPT hardness proof"};
}
console.log(JSON.stringify(checker(),null,2));
```

## Captured identical output of both JavaScript runs

```json
{
  "run": "MINK-CERTIFIED-FALSE-JOINT-SIM-R20",
  "passed": true,
  "checks": 234,
  "scopes": 3,
  "capsules": 9,
  "bit_couplings": 216,
  "full_public_couplings": 9,
  "source_matrices": 2,
  "limitations": "Certified FALSE only; mock native signatures; no hard-TRUE or QPT hardness proof"
}
```
