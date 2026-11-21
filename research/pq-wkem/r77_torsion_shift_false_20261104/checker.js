function runR77() {
  const q=4096,p=256,Delta=1024,s=q/p,Lambda=Delta/s;
  let checks=0,rng=0x771104>>>0;
  const test=(b,msg)=>{checks++;if(!b)throw new Error(msg+" assertion "+checks)};
  const next=()=>{rng^=rng<<13;rng^=rng>>>17;rng^=rng<<5;return rng>>>0};
  const ri=n=>next()%n, mod=(a,n)=>(a%n+n)%n;
  const hash=a=>{let h=2166136261>>>0;for(const c of JSON.stringify(a))h=Math.imul(h^c.charCodeAt(0),16777619)>>>0;return h.toString(16)};
  const source=(A,z,e,mu,Q,P,D)=>{const sp=Q/P;return A.map((a,i)=>Math.floor((mod(a*z+e[i]+(i===0?D*mu:0),Q)+sp/2)/sp)%P)};
  const choices=[[-1,4,4],[-1,8,8]];
  const small={};
  for(const [k,A] of choices.entries()) {
    const t=12;
    test(mod(-t,16)===4 && A.slice(1).every(v=>mod(v*t,16)===0),"torsion certificate 16");
    test(A.slice(1).some(v=>mod(v*15,16)!==0),"old image criterion fails");
    let hist=[];
    for(let mu=0;mu<4;mu++) {
      const H=new Map();
      for(let z=0;z<16;z++)for(let ea=-1;ea<=1;ea++)for(let eb=-1;eb<=1;eb++)for(let ec=-1;ec<=1;ec++) {
        const key=JSON.stringify(source(A,z,[ea,eb,ec],mu,16,16,4));
        H.set(key,(H.get(key)||0)+1);
      }
      hist.push(H);
    }
    for(let mu=1;mu<4;mu++) {
      test(hist[mu].size===hist[0].size,"same support");
      for(const [key,count] of hist[0]) test(hist[mu].get(key)===count,"exact full histogram");
    }
    small[k===0?"4a+4b-1":"8a+8b-1"]=hist[0].size;
  }
  const neg=[-1,2,2],N=[];
  for(let mu=0;mu<2;mu++) {
    const H=new Map();
    for(let z=0;z<16;z++) {
      const k=JSON.stringify(source(neg,z,[0,0,0],mu,16,16,4));
      H.set(k,(H.get(k)||0)+1);
    }
    N.push(H);
  }
  test(!Array.from({length:16},(_,t)=>t).some(t=>mod(-t,16)===4&&mod(2*t,16)===0),"negative no shift");
  test([...N[0]].some(([key,count])=>N[1].get(key)!==count),"negative distributions distinct");
  test(Lambda>2*4*(1/s+0.5)&&p-3*Lambda>2*4*(1/s+0.5),"correctness spacing");
  for(const A of choices) {
    test(mod(-3072,q)===Delta&&A.slice(1).every(v=>mod(v*3072,q)===0),"compressed torsion certificate");
    test(A.slice(1).some(v=>mod(-v,q)!==0),"not old e0-image certificate");
    for(let a=0;a<2;a++)for(let b=0;b<2;b++)test(mod(A[0]+A[1]*a+A[2]*b,q)!==0,"original false");
  }
  let couplings=0,selected=[0,0];
  for(let j=0;j<160;j++) {
    const Acom=Array.from({length:6},()=>Array.from({length:3},()=>ri(256)));
    const zL=Array.from({length:3},()=>ri(256));
    const eL=Array.from({length:6},()=>ri(2)?1:-1);
    const U=Acom.map((row,i)=>mod(row.reduce((v,a,t)=>v+a*zL[t],0)+eL[i],256));
    const K=zL[0]+256*zL[1]+65536*zL[2]+eL.reduce((v,e,i)=>v+(e===1?1:0)*2**(24+i),0);
    const words=Array.from({length:15},(_,i)=>Math.floor(K/2**(2*i))%4);
    const sig=[ri(256),ri(256)],Dsig=sig.map((v,i)=>v^U[i]);
    const ctx=["R77","ORIGINAL NP relation","utxo:scope","challenge branch","anchors","native pk"];
    const CK=hash([ctx,Acom,U,Dsig]);
    const make=A=>{
      const real=[],sim=[];
      for(const mu of words) {
        const z=ri(q),e=Array.from({length:3},()=>ri(3)-1);
        real.push(source(A,z,e,mu,q,p,Delta));
        sim.push(source(A,mod(z+mu*3072,q),e,0,q,p,Delta));
      }
      test(JSON.stringify(real)===JSON.stringify(sim),"complete SOURCE exact coupling");
      return [real,sim];
    };
    const [H1,S1]=make(choices[0]);
    const index=parseInt(hash([CK,H1]),16)%2;
    selected[index]++;
    const [H2,S2]=make(choices[index]);
    const sibling={independentRootOpening:ri(256),claim:"different-UTXO"};
    const full=(c1,c2)=>{
      const CK1=hash(["CK1",ctx,CK,c1]),CK2=hash(["CK2",CK1,index,c2]);
      const Aux=hash(["Aux",ctx,CK1,CK2,sibling]);
      return {ctx,Acom,Dsig,CK,CK1,CK2,C:[c1,c2],sibling,Aux,
        corruptOutput:hash(["malicious postprocess",Aux,CK2,CK,sibling])};
    };
    test(JSON.stringify(full(H1,H2))===JSON.stringify(full(S1,S2)),"entire public view exact coupling");
    couplings++;
  }
  const Atrue=[-1,1,1,1],R=[[1,1,0,0],[1,0,1,0],[1,0,0,1]];
  let opens=0;
  for(let j=0;j<80;j++){
    const mu=Array.from({length:24},()=>ri(4));
    const Cs=mu.map(w=>source(Atrue,ri(q),Array.from({length:4},()=>ri(3)-1),w,q,p,Delta));
    for(const r of R) {
      test(r.reduce((v,x,i)=>v+x*Atrue[i],0)===0,"ORIGINAL evaluation");
      const recovered=Cs.map(C=>{
        const y=mod(r.reduce((v,x,i)=>v+x*C[i],0),p);
        const dist=Array.from({length:4},(_,v)=>Math.min(mod(y-Lambda*v,p),mod(Lambda*v-y,p)));
        const idx=dist.indexOf(Math.min(...dist));
        test(dist[idx]<Lambda/2,"opening tolerance");
        return idx;
      });
      test(JSON.stringify(mu)===JSON.stringify(recovered),"every ORIGINAL witness same root");
      opens++;
    }
  }
  return {run:"R77-TORSION-SHIFT-FALSE-20261104",status:"STRICT_CERTIFIED_FALSE_CLASS_EXTENSION__NOT_GENERIC_WKEM",assertions:checks,
    exact_toy_histogram_support:small,full_view_lwe_challenge_couplings:couplings,
    adaptive_second_statement_selection:selected,valid_original_witnesses:3,successful_true_openings:opens,
    limitations:"toy LWE and toy hashes; no QPT security proof or hard TRUE recovery-to-ORIGINAL witness reduction"};
}
console.log(JSON.stringify(runR77(),null,2));
