# SOURCE seed-wrap KEM–DEM: restricted constructive composition (2026-10-30)

**STATUS: positive SOURCE-only release composition and conditional 41.03% public-data saving, NOT a solved ORIGINAL-witness post-quantum WKEM.** No new ORIGINAL-compiler or arbitrary-recovery-to-ORIGINAL-witness reduction. Research-only, off-line: no external sources. The new saving requires an **ADDITIONAL independently justified nonuniform-QPT PRG assumption**, so it is not an LWE-only improvement under identical assumptions.

## Exact continuity and previous component

Repository syscoin/PVUGC, open/draft/unmerged PR #1, branch research/pq-wkem-validation-20260918. This run starts at SHA 87601217ae2927c7966e298fb94c76eb7c98e801; last substantive PR comment inspected 6538023693. The exact current predecessor source-independent-Lift obstruction is research/pq-wkem/source_independent_lift_gate_20261030/RESEARCH.md (blob 9d472b6e5b432ee6f9e61dd225f5bd7f68c14f0b), and the previous 512-bit native-secret SOURCE release is research/pq-wkem/native_256bit_master_20261030/RESEARCH.md (blob 3d992b47ab3dec20f2badd60bfceadf07c26f0e8).

Previously, 64-byte Shamir shares were directly LWE-encrypted digit-by-digit: L=103 base-32 symbols per packet. Here each packet instead encrypts its own independent 32-byte session seed (52 base-32 symbols) under ordinary vector dual-LWE and masks the whole 64-byte Shamir share with a 256-to-512-bit domain-separated QPT-PRG. One packet opening still releases precisely one Shamir share, and any two releases recover the same precommitted native master. This does NOT repair the previously proved known-TRUE-to-FALSE scope-transfer when SOURCE sampling is unrelated to the ORIGINAL statement.

## Explicit honest classical-PPT algorithms and distributions

Use illustrative q=16,777,213 prime, n=256, m=4469, signed-unit weight w=2004, g=524287, and independent centered errors chi uniform over [-128,128]. Sample one genuinely uniform A in F_q^(n x m) shared across honestly independently generated signer/scopes. Draw actual native 256-parameter 32-byte SK.seed, independent 32-byte SK.prf and PUBLIC 32-byte PK.seed. Derive the **genuine** native pk via real KeyGenFromSeeds, and let K=SK.seed||SK.prf, a 64-byte master. The checker uses a mock and makes NO native implementation claim. Choose an independent uniform 64-byte Shamir slope V over GF(256) and set S_i=K+alpha_i V bytewise, with alpha_i in {1,2,3}.

Authenticated public ctx must bind relation identity, ORIGINAL statement, actual claim/UTXO, branch, source anchors/window, intended challenge path/verification key and a manifest without self-referential key derivation. For each packet index i independently and privately sample session seed F_i uniform {0,1}^256. Encode it as L=52 little-endian 5-bit digits a_(i,l), restricting the final digit to {0,1}. For EACH i,l sample a hidden planted short Z_(i,l) uniformly from T = {z in {-1,0,1}^m : weight(z)=w}; set public U_(i,l)=A Z_(i,l) modulo q. Sample packet-specific r_i uniform F_q^n, e_c,i from chi^m, e_d,i from chi^52. Publish:

    c_i = A^T r_i + e_c,i;
    d_(i,l) = U_(i,l)^T r_i + e_d,(i,l) + g a_(i,l) mod q;
    h_i = S_i XOR G(F_i,ctx,i)   (64 bytes).

All F_i, Z_(i,l), r_i, errors and slopes are independently fresh across packet, signer and scope. Never reuse the same F for two packets, because one opening would then allow expansion of both masks. Concretely for a standard hash-XOF implementation candidate one may set G(F,ctx,i)=SHAKE256("PVUGC-PQWKEM-SOURCE-SEEDWRAP-v1"||len(ctx)_(4BE)||ctx||i_(1B)||F,64 bytes). This fixed SHAKE construction is NOT shown to satisfy QPT PRG security here: **nonuniform-QPT pseudorandomness of G with public, efficiently selectable independent context is an explicit extra assumption**, not a theorem derived from SHAKE collision resistance, native EUF, or LWE.

The complete public view is (R_original,x, A, all U,c,d,h, genuine native pk, context/auxiliary, related capsules, manifest and permitted native signing transcript). The private planted Z do not come from an ORIGINAL witness; no SourceOpen oracle is assumed.

**Public OFF-CHAIN OpenPacket(i,z_(i,1..52)).** Check all z are signed-unit weight w and A z_(i,l)=U_(i,l). Decode the nearest cyclic alphabet symbol from d_(i,l)-z_(i,l)^T c_i to recover all 52 digits and reject a noncanonical final digit. Recover F_i; compute S_i=h_i XOR G(F_i,ctx,i). **Recover(i,j)** for any TWO DISTINCT opened packet indices interpolates the unique K from S_i,S_j over GF(256), verifies it against the actual native pk and public PK.seed, and generates the ordinary native challenge-path signature OFF CHAIN. No general proof, NP circuit, VM step, PCP/BitVM trace dispute or signature derivation is assumed available inside Bitcoin.

For ANY accepted weight-w source z (not only the planted one), the residual is g*a+e_d-z^T e_c. Thus |noise|<=B(w+1)=256640; strict gaps are g-2B(w+1)=11007 and q-31g-2B(w+1)=11036. Every accepted source opening decodes the SAME authentic F_i. Distinct valid openings may retain distinct state. Any two distinct packets always reconstruct the SAME precommitted K exactly. This is SOURCE correctness, not an ORIGINAL compiler.

## Full-joint-public QPT theorem opportunity: restricted, explicitly conditional

Assume ordinary nonuniform-QPT decisional-LWE for uniformly sampled matrix [A|U] in F_q^(n x (m+52)), fresh independent r_i and chi; nonuniform-QPT secure 256-to-512-bit PRG G in all allowed public contexts with independent F_i; nonuniform-QPT native 256-parameter EUF-CMA; QPT scope/manifest authentication. The QPT adversary may coherently process the classical joint public distribution, have independent quantum advice, inspect independently generated related capsules and permitted signatures, and adaptively disclose classical planted SOURCE openings and/or full encryption coins of **at most ONE packet index** in the protected signer/claim scope. Quantum-superposition disclosure queries, actual ORIGINAL-dependent correlated sources/openings, adversarial N-1 planted-source setup/unknown-one-honest coinflip and abort grinding, or hidden-correlated advice are EXCLUDED. Other scopes must be independently generated or straight-line simulatable using ONLY the visible joint challenge.

For each protected two-packet pair P, the remaining packet k may be fully opened. Statistical planted-target replacement: conditioned on the exactly simulated k-side planted Z_k and all public coins, each of the 2L protected target columns (A Z_j) is epsilon-close to an independently uniform column, epsilon<=0.5 sqrt((q^n-1)/(2^w binom(m,w))), because A is honestly uniform and Z_j independent; total variation <=2L epsilon. Keep all k-side U,Z, coins and disclosure **exactly**. The postprocessing includes native pk, h and all allowed public aux.

Two straight-line ordinary vector-LWE hybrids make protected c_j,d_j uniform independent of their encrypted F_j, with true K, native pk, S_i and h_i available to the reduction and without needing the hidden challenge r. Two independent QPT-PRG hybrids then replace protected G(F_j,ctx,j) by uniform 512-bit strings. They apply only AFTER the protected LWE ciphertexts cease to depend on F_j. The PRG embedding knows K and S_j and can authentically generate all permitted public context. Now protected h_j are uniform independent of K. The remaining possibly exposed S_k=K+alpha_k V is exactly uniform independent of K and the genuine pk. The final native-EUF adversary therefore sees pk, legitimate signing transcript and unrelated independent public data; it cannot recover a usable K or sign a fresh scoped challenge unless it breaks native QPT EUF-CMA. No rewinding or automatic lifting of classical claims to QPT is used.

If E_P is the successful unauthorized native forgery/recovery event without disclosure in P, then the proof yields the **restricted** bound

    Pr[win] <= 3*(2L*epsilon + 2 Adv_QPT-LWE + 2 Adv_QPT-PRG + Adv_QPT-native-EUF + Adv_QPT-auth).

The union over the three protected pairs handles adaptive leakage of at most one packet. For 400 signer/scopes apply a 400 factor to EVERY term, not only the statistical one, or prove a proper multiuser variant. Exposed SOURCE openings are honestly sampled and are not derived from any ORIGINAL witness. This bound is not the missing generic FALSE-instance or hard-TRUE reduction.

For 400 scopes J=400*3*2*52=124800, the exact integer condition
J^2 (q^n-1) 2^256 <= 4 * 2^w * binom(m,w)
first holds at w=2004 (fails at 2003), with log2(J epsilon) approximately -128.19808. This is a STATISTICAL term only, not calibrated 128-bit complete QPT security.

## Concrete public resource accounting

Previously for L=103: A + 400*3 packets of SOURCE U and LWE c,d = 114,816,192 bytes. After seed wrapping: A + 400*(3*n*52 + 3*(m+52))*3 bytes + 400*3*64 bytes in masked Shamir shares = **67,707,792 bytes**, a saving of 47,108,400 bytes (41.0294%). This excludes native pk/signatures, setup transcript, BTC data and ORIGINAL evidence. It also ADDS a QPT-PRG premise; the efficiency cannot honestly be advertised as preserving an LWE-only proof.

## Exactly tested, not proved by code

The appended self-contained JS checker source was executed once as a real V8 function in this run. It checks 24 64-byte master trials, 72 SOURCE packet releases, both representations for each of 3,744 explicitly different accepted SOURCE openings, all 3 pair combinations, GF256 one-share uniform conditional on a revealed byte, canonical 52-digit seed decoding, exact BigInt weight threshold, margins and byte accounting. Its toy deterministic PRG is **deliberately cryptographically insecure**, used only to verify XOR/reconstruction, and its duplicated A column makes the toy SOURCE distribution deliberately nonuniform. Separately, the exact Python stdlib checker in the local downloadable archive passed 32,920 assertions TWICE with byte-identical output; that checker uses hashlib SHAKE256 for the actual 64-byte mask, but does not establish its QPT security. Neither test runs SLH native signing or tests a QPT adversary.

## Exact ORIGINAL-witness handoff; this is NOT completed WE

Missing witness-free honest classical-PPT Comp(R_original,x,ctx,pk), public Lift(x,W,...), joint original-conditioned LWE challenge simulator, generic FALSE-instance complete-public secrecy, and arbitrary unauthorized hard-TRUE recovered K/native forgery -> actual ORIGINAL witness or independent PQ break (without adversary-volunteered representation). The previous **dummy known-TRUE to FALSE** transfer applies unchanged to this SOURCE-only construction if ORIGINAL x is merely attached as a public label. The 256-bit PRG does NOT fix that. Required exact equation:

    For every W: R_original(x,W)=1 => Recover(Lift(x,W,Comp(R_original,x,ctx,pk))) = K*,

together with a full-public QPT reduction whose simulator includes actual source-conditioned setup/opening/aux/checking-key/related-capsule correlations without the unknown challenge secret. The reduction must not assume WE/iO/WPRF as an unexplained oracle or ask the adversary to supply z. Malicious one-honest N-of-N erasure/build and abort/DA, SYS/BTC qualified forks/intervals, and the conditional native PQ no-EC-key-path Bitcoin endpoint remain unproved. No production/main/workflows, merge, transfer, funding or deployment is authorized.

## Exact executed JavaScript checker source

```js
const runCheck = function runCheck(){
  let checks=0;
  const ck=(yes,msg)=>{checks++;if(!yes) throw Error("CHECK "+msg);};
  const rng=(()=>{let s=20261030;return ()=>{s^=(s<<13);s^=(s>>>17);s^=(s<<5);return(s>>>0);};})();
  const randint=(n)=>rng()%n;
  const mul=(a,b)=>{let v=0;while(b){if(b&1)v^=a;a=((a<<1)&255)^((a&128)?27:0);b>>=1;}return v;};
  const inverse=(a)=>{for(let j=1;j<256;j++)if(mul(a,j)===1)return j;throw Error("inverse");};
  const reconstruct=(a,b,S,T)=>{
    const den=inverse(a^b);return S.map((x,i)=>x^mul(a,mul(x^T[i],den)));
  };
  const bytes=(n)=>Array.from({length:n},()=>randint(256));
  const dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
  const wrap=(x,q)=>((x%q)+q)%q;
  const toyStretch=(seed,ctx,i)=>Array.from({length:64},(_,k)=>seed[k%32]^((i+1)*37)^((k*17)&255)^ctx[k%ctx.length]);
  const encode=(seed)=>{let acc=0n;for(let i=0;i<32;i++)acc|=BigInt(seed[i])<<BigInt(8*i);return Array.from({length:52},(_,j)=>Number((acc>>BigInt(5*j))&31n));};
  const decode=(digits)=>{ck(digits.length===52&&digits[51]<2,"seed canonical");let x=0n;for(let j=0;j<52;j++)x|=BigInt(digits[j])<<BigInt(5*j);return Array.from({length:32},(_,j)=>Number((x>>BigInt(8*j))&255n));};
  const q=65521,g=2047,n=3,m=12,w=4,B=1,L=52,alphas=[1,2,3],ctx=[11,19,31,47,53,61];
  let altOpenings=0,pairs=0,packets=0;
  for(let trial=0;trial<24;trial++){
    const A=Array.from({length:n},()=>Array.from({length:m},()=>randint(q)));
    for(let k=0;k<n;k++)A[k][1]=A[k][0];
    const K=bytes(64),V=bytes(64),masked=[],sealed=[],open=[];
    for(let i=0;i<3;i++){
      const S=K.map((b,j)=>b^mul(alphas[i],V[j]));
      const F=bytes(32), stream=toyStretch(F,ctx,i),h=S.map((b,j)=>b^stream[j]);
      const r=Array.from({length:n},()=>randint(q));
      const ec=Array.from({length:m},()=>randint(2*B+1)-B);
      const ed=Array.from({length:L},()=>randint(2*B+1)-B);
      const c=Array.from({length:m},(_,j)=>wrap(A.reduce((s,row,k)=>s+row[j]*r[k],ec[j]),q));
      const zs=[],us=[],a=encode(F);
      for(let ell=0;ell<L;ell++){
        const z=Array(m).fill(0),positions=new Set([0]);
        while(positions.size<w)positions.add(2+randint(m-2));
        for(const j of positions)z[j]=randint(2)?1:-1;
        zs.push(z);us.push(A.map(row=>wrap(dot(row,z),q)));
      }
      const d=us.map((u,ell)=>wrap(dot(u,r)+ed[ell]+g*a[ell],q));
      masked.push(h);sealed.push({c,d,us,F});open.push(zs);
    }
    const shares=[];
    for(let i=0;i<3;i++){
      const {c,d,us,F}=sealed[i],out=[];
      for(let ell=0;ell<L;ell++){
        const z=open[i][ell],alt=z.slice();alt[1]=alt[0];alt[0]=0;
        ck(alt[1]!==0 && alt[0]===0 && alt.some((v,j)=>v!==z[j]),"distinct opening");
        ck(A.every((row,j)=>wrap(dot(row,alt),q)===us[ell][j]),"same source target");
        ck(z.reduce((s,a)=>s+Math.abs(a),0)===w,"original short opening");
        ck(alt.reduce((s,a)=>s+Math.abs(a),0)===w,"alternative short opening");
        let recoveredDigit=-1;
        for(const candidate of [z,alt]){
          const y=wrap(d[ell]-dot(candidate,c),q);
          let best=-1,bestDistance=q;
          for(let bit=0;bit<32;bit++){
            const t=wrap(y-g*bit,q),dst=Math.min(t,q-t);
            if(dst<bestDistance){best=bit;bestDistance=dst;}
          }
          ck(best===encode(F)[ell],"legal opening restores session seed");
          if(recoveredDigit<0)recoveredDigit=best;
          else ck(recoveredDigit===best,"same digit via two distinct openings");
        }
        out.push(recoveredDigit);altOpenings++;
      }
      const got=decode(out);
      ck(got.every((b,j)=>b===F[j]),"32-byte session seed");
      const s=masked[i].map((b,j)=>b^toyStretch(got,ctx,i)[j]);
      shares.push(s);packets++;
    }
    for(const [i,j] of [[0,1],[0,2],[1,2]]){
      const recovered=reconstruct(alphas[i],alphas[j],shares[i],shares[j]);
      ck(recovered.every((b,k)=>b===K[k]),"same 512-bit precommitted master");
      pairs++;
    }
  }
  for(const a of alphas){
    const inv=inverse(a);
    for(const revealedShare of [0,47,255]){
      const seen=new Set();
      for(let k=0;k<256;k++){
        const v=mul(k^revealedShare,inv);
        ck((k^mul(a,v))===revealedShare,"Shamir equation");
        seen.add(k);
      }
      ck(seen.size===256,"one share leaves all K values");
    }
  }
  const choose=(n,k)=>{let a=1n;for(let i=1;i<=k;i++)a=a*BigInt(n-i+1)/BigInt(i);return a;};
  const qL=16777213n,nL=256,mL=4469,J=400n*3n*2n*52n;
  const checkWeight=(ww)=>4n*(1n<<BigInt(ww))*choose(mL,ww) >= J*J*(qL**BigInt(nL)-1n)*(1n<<256n);
  ck(!checkWeight(2003)&&checkWeight(2004),"exact 400-scope statistical threshold");
  const E=128*(2004+1);
  ck(524287-2*E===11007 && 16777213-31*524287-2*E===11036,"worst-case decoding margins");
  const old=3*256*4469+400*(3*256*103+3*(4469+103))*3;
  const newer=3*256*4469+400*(3*256*52+3*(4469+52))*3+400*3*64;
  ck(old===114816192 && newer===67707792,"exact storage accounting");
  return {checks,toy_trials:24,packet_releases:packets,distinct_accepted_alternate_openings:altOpenings,shamir_pair_recoveries:pairs,
  qpt_security_proof_tested:false,native_signature_tested:false,toy_dem_is_cryptographically_secure:false,
  old_bytes:old,new_bytes:newer,saved_bytes:old-newer,save_pct:100*(old-newer)/old,
  statistical_threshold_weight:2004,statistical_prev_weight_fails:2003,
  original_witness_compiler:"NOT INSTANTIATED",subject:"restricted source KEM-DEM; PRG is ADDED independent QPT assumption"};
};
console.log(JSON.stringify(runCheck(),null,2));

```

## Captured actual V8 checker result

```json
{
  "checks": 28740,
  "toy_trials": 24,
  "packet_releases": 72,
  "distinct_accepted_alternate_openings": 3744,
  "shamir_pair_recoveries": 72,
  "qpt_security_proof_tested": false,
  "native_signature_tested": false,
  "toy_dem_is_cryptographically_secure": false,
  "old_bytes": 114816192,
  "new_bytes": 67707792,
  "saved_bytes": 47108400,
  "save_pct": 41.02940463310262,
  "statistical_threshold_weight": 2004,
  "statistical_prev_weight_fails": 2003,
  "original_witness_compiler": "NOT INSTANTIATED",
  "subject": "restricted source KEM-DEM; PRG is ADDED independent QPT assumption"
}
```
