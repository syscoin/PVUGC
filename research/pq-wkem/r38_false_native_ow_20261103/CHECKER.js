const report = (function checker(){
  let checks=0,seed=38038;
  function ok(v,msg){if(!v)throw Error(msg); checks++}
  function rnd(n){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n}
  const q=101,D=50,N=4,L=3;
  function mod(v){return ((v%q)+q)%q}
  function polyMul(a,b){let r=Array(16).fill(0);for(let i=0;i<16;i++)for(let j=0;j<16;j++)r[i|j]+=a[i]*b[j];return r}
  function failure(y){let f=[1,...Array(15).fill(0)];for(let i=0;i<3;i++){let t=Array(16).fill(0);if(y&(1<<i))t[1<<i]=1;else{t[0]=1;t[1<<i]=-1}f=polyMul(f,t)}return f}
  function evalAt(p,z){let v=0;for(let i=0;i<16;i++)if((z&i)===i)v+=p[i];return v}
  const f=Array.from({length:8},(_,j)=>failure(j));
  const unit=Array(16).fill(0);
  for(let i=0;i<8;i++){
    const sq=polyMul(f[i],f[i]);ok(JSON.stringify(sq)===JSON.stringify(f[i]),"idempotent");
    for(let j=0;j<8;j++)if(i!==j)ok(polyMul(f[i],f[j]).every(v=>v===0),"orthogonal");
    for(let k=0;k<16;k++)unit[k]+=sq[k]
  }
  ok(unit[0]===1&&unit.slice(1).every(v=>v===0),"exact integer unit");
  for(let z=0;z<16;z++)ok(f.reduce((a,p)=>a+evalAt(p,z),0)===1,"false 3CNF");
  const pairs=[];for(let i=0;i<8;i++)for(let j=i;j<8;j++)pairs.push([i,j]);
  const gens=pairs.map(([i,j])=>polyMul(f[i],f[j]));
  const diag=pairs.map(([i,j],k)=>i===j?k:-1).filter(k=>k>=0);
  ok(gens.length===36&&diag.length===8,"real product generator set");
  function build(a,e,mu,gs){let c=e.map(v=>v);for(let k=0;k<gs.length;k++)for(let u=0;u<16;u++)c[u]+=a[k]*gs[k][u];c[0]+=D*mu;return c.map(mod)}
  function bits(sig){return sig.flatMap(s=>Array.from({length:5},(_,j)=>(s>>j)&1))}
  function H(x){return (x*x)%17} // Deliberately insecure toy hash, NOT a QPT assumption.
  function msg(pk,ctx){let t=ctx*37;for(let j=0;j<L;j++)for(let b=0;b<2;b++)t=(t*5+pk[j][b]+3)%65537;return Array.from({length:L},(_,j)=>(t>>j)&1)}
  function key(x,b,ctx){let sk=Array.from({length:L},()=>[rnd(17),rnd(17)]);sk[0][b]=x;let pk=sk.map(p=>p.map(H)),m=msg(pk,ctx);return {pk,m,sigma:sk.map((p,j)=>p[m[j]])}}
  function view(pk,m,caps,ctx){let s=JSON.stringify({statement:"all-8-clause-false",pk,m,caps,ctx});let ck=0;for(let k=0;k<s.length;k++)ck=(Math.imul(ck,131)+s.charCodeAt(k))>>>0;let aux=(ck^0x9e3779b9)>>>0;return JSON.stringify({pk,m,ctx,caps,ck,aux})}
  let couplings=0,fullView=0,extractions=0,correct=0;
  for(let trial=0;trial<32;trial++){
    const x=rnd(17),b=rnd(2),ctx=trial+777,{pk,m,sigma}=key(x,b,ctx);
    let real=[],zero=[];
    for(let scope=0;scope<3;scope++){
      let r=[],z=[];
      for(const mu of bits(sigma)){
        let a=Array.from({length:36},()=>rnd(q)),e=Array.from({length:16},()=>rnd(2)?1:-1);
        let c=build(a,e,mu,gens),shift=a.slice();
        for(const j of diag)shift[j]=mod(shift[j]+D*mu);
        let c0=build(shift,e,0,gens);
        ok(JSON.stringify(c)===JSON.stringify(c0),"whole vector coupling");
        r.push(c);z.push(c0);couplings++;
      }
      real.push(r);zero.push(z)
    }
    ok(view(pk,m,real,ctx)===view(pk,m,zero,ctx),"entire public view equality");
    fullView++;
    let forged=Array.from({length:L},(_,j)=>Array.from({length:17},(_,k)=>k).find(k=>H(k)===pk[j][m[j]]));
    ok(forged.every((v,j)=>H(v)===pk[j][m[j]]),"brute toy hash");
    if(b===m[0]){ok(H(forged[0])===H(x),"OW embedding");extractions++}
  }
  const genTrue=pairs.filter(([i,j])=>i!==5&&j!==5).map(([i,j])=>polyMul(f[i],f[j]));
  const valid=Array.from({length:16},(_,z)=>z).filter(z=>f.every((p,j)=>j===5||evalAt(p,z)===0));
  ok(JSON.stringify(valid)==="[5,13]","two distinct original witnesses");
  for(let t=0;t<32;t++){
    let {sigma}=key(rnd(17),rnd(2),t+1000);
    for(const mu of bits(sigma)){
      let a=Array.from({length:genTrue.length},()=>rnd(q)),e=Array.from({length:16},()=>rnd(2)?1:-1),c=build(a,e,mu,genTrue);
      for(const z of valid){
        let v=mod(evalAt(c,z)),d0=Math.min(v,q-v),w=mod(v-D),d1=Math.min(w,q-w);
        ok((d1<d0?1:0)===mu,"same presignature recovery");correct++
      }
    }
  }
  return {run:"R38-FALSE-NATIVE-OW",assertions:checks,false_clauses:8,false_generators:36,integer_unit_certificate_terms:8,full_public_view_equalities:fullView,exact_bit_capsule_couplings:couplings,true_original_witnesses:valid,true_witness_decodings:correct,matched_ow_embedding:extractions,trials:32,hash:"INSECURE square modulo 17 for finite toy checks",status:"restricted algebra and simulator; no QPT hardness measurement"}
})();
console.log(JSON.stringify(report, null, 2));
