function checkR75() {
  let assertions=0, seed=0x751104>>>0, couplings=0, transcripts=0;
  const ok=(v,s)=>{assertions++;if(!v)throw Error(`${s} at ${assertions}`)};
  const rnd=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0};
  const mod=(x,q)=>(x%q+q)%q;
  const A2=[[1,0,0,0,0],[-1,1,0,0,0],[-1,0,1,0,0],[1,0,0,1,1]];
  const A2p=[A2[0],A2[2],A2[3],A2[1]];
  const A3=[[1,0,0,0,0,0,0,0],[-1,1,0,0,0,0,0,0],[-1,0,1,0,0,0,0],[-1,0,0,1,0,0,0,0],[1,0,0,0,1,0,0,0],[1,0,0,0,0,1,0,0],[1,0,0,0,0,0,1,0],[-1,0,0,0,0,0,0,1]];
  const t2=[1,1,1,-1,0], t3=[1,1,1,1,-1,-1,-1,1];
  const falseTypes=[["F2",A2,t2],["F2-permuted",A2p,t2],["F3",A3,t3]];
  const matvec=(A,z,q)=>A.map(r=>mod(r.reduce((a,b,i)=>a+b*z[i],0),q));
  const source=(A,z,e,mu,q,s,Delta)=>matvec(A,z,q).map((v,i)=>mod(Math.floor((mod(v+e[i]+(i===0?Delta*mu:0),q)+s/2)/s),q/s));
  const shifted=(z,t,mu,Delta,q)=>z.map((v,i)=>mod(v+Delta*mu*t[i],q));
  for(const [n,A,t] of falseTypes) {
    const o=matvec(A,t,65536);
    ok(o.every((v,i)=>v===(i===0?1:0)),`certificate ${n}`);
  }
  const hash=x=>{let h=2166136261>>>0;for(const c of JSON.stringify(x))h=Math.imul(h^c.charCodeAt(0),16777619)>>>0;return h>>>0};
  const K=Array.from({length:32},()=>rnd()%16);
  const U=Array.from({length:96},(_,i)=>hash(["NONCRYPTO-PRG",K,i])%256);
  const sigma=Array.from({length:64},(_,i)=>hash(["INDEPENDENT-TOY-SIGNATURE",i])%256);
  const Dsig=sigma.map((v,i)=>v^U[i]);
  const scope=["ORIGINAL-NP","claim:UTXO:0","challenge-path","anchors:window","native-vpk"];
  const CK0=hash(["CK0",scope,Dsig,U.slice(64)]);
  for(let run=0;run<128;run++){
    let history=[];
    for(let step=0;step<1+run%4;step++){
      const choice=hash(["choose",scope,CK0,history,step])%falseTypes.length;
      const [name,A,t]=falseTypes[choice];
      const CR=[],CS=[];
      for(const mu of K){
        const z=Array.from({length:t.length},()=>rnd()%65536);
        const e=Array.from({length:A.length},()=>rnd()%3-1);
        CR.push(source(A,z,e,mu,65536,16,256));
        CS.push(source(A,shifted(z,t,mu,256,65536),e,0,65536,16,256));
      }
      ok(JSON.stringify(CR)===JSON.stringify(CS),"same-root source translation");
      const full=c=>{
        const CK=hash(["CK",CK0,name,step,history,c]);
        const aux=hash(["Aux",scope,CK,c,history]);
        const related=hash(["preauthorized-related-slot",scope,aux]);
        const maliciousPost=hash(["adaptive-QPT-public-output-fixture",CK,aux,related,history]);
        return [name,step,c,Dsig,CK,aux,related,maliciousPost];
      };
      ok(JSON.stringify(full(CR))===JSON.stringify(full(CS)),"complete CK/Aux correlated view");
      history.push(hash(full(CR)));
      couplings++;
    }
    transcripts++;
  }
  // Exhaust 3^5 * 3^5 ordered source-coin pairs, for each of three root values.
  const seeds=[];for(let i=0;i<243;i++){let j=i,z=[];for(let h=0;h<5;h++){z.push(j%3);j=Math.floor(j/3)}seeds.push(z)}
  const hist=[];
  for(let mu=0;mu<3;mu++){
    const H=new Map();
    for(const z of seeds){
      const c1=source(A2,z,[0,0,0,0],mu,3,1,1);
      const A=(c1[0]%2===0)?A2:A2p;
      for(const z2 of seeds){
        const c2=source(A,z2,[0,0,0,0],mu,3,1,1);
        const key=JSON.stringify([c1,c2]);
        H.set(key,(H.get(key)||0)+1);
      }
    }
    hist.push(H);
  }
  for(let u=1;u<3;u++){
    ok(hist[0].size===hist[u].size,"exact adaptive histogram support");
    for(const [k,n] of hist[0])ok(hist[u].get(k)===n,"exact adaptive same-root joint histogram");
  }
  ok([...hist[0].values()].reduce((a,b)=>a+b,0)===59049,"exact pairs per root");
  const AT=[[1],[-1],[-1],[1]],trueRs=[[1,1,0,0],[1,0,1,0],[1,1,1,1]];
  const tc=K.map(mu=>source(AT,[rnd()%65536],Array.from({length:4},()=>rnd()%3-1),mu,65536,16,256));
  for(const r of trueRs){
    ok(r.reduce((a,v,i)=>a+v*AT[i][0],0)===0,"genuine ORIGINAL kernel");
    const recovered=tc.map(c=>{
      const y=mod(c.reduce((a,v,i)=>a+v*r[i],0),4096);
      const distances=Array.from({length:16},(_,u)=>Math.min(mod(y-16*u,4096),mod(16*u-y,4096)));
      const idx=distances.indexOf(Math.min(...distances));
      ok(distances[idx]<8,"honest decoding");
      return idx;
    });
    ok(JSON.stringify(recovered)===JSON.stringify(K),"all ORIGINAL witness same root");
  }
  // Two excluded attacks: publicly opened same-root TRUE sibling, and source randomness reuse.
  for(let mu=0;mu<16;mu++){
    const z=[rnd()%65536],c=source(AT,z,[0,0,0,0],mu,65536,16,256);
    ok(mod(c[0]+c[1],4096)===16*mu,"TRUE sibling releases common root");
  }
  for(let a=0;a<3;a++)for(let b=0;b<3;b++){
    const z=Array.from({length:5},()=>rnd()%3);
    const ca=source(A2,z,[0,0,0,0],a,3,1,1),cb=source(A2,z,[0,0,0,0],b,3,1,1);
    ok(mod(ca[0]-cb[0],3)===mod(a-b,3),"reused coins reveal difference");
  }
  return {run:"R75-ADAPTIVE-SAME-ROOT-CERTIFIED-FALSE-20261104",status:"RESTRICTED_CERTIFIED_FALSE_COMPOSITION__NOT_GENERIC_WKEM",assertions,source_fullview_couplings:couplings,adaptive_transcripts:transcripts,exact_root_values:3,joint_seed_pairs_per_root:59049,joint_support:hist[0].size,true_original_witnesses:3,true_sibling_leak_controls:16,reused_coins_negative_controls:9,limitations:"Toy FNV and parameters, no QPT hardness or hard-TRUE recovery-to-ORIGINAL witness reduction"};
}
console.log(JSON.stringify(checkR75(),null,2));
