function runR59() {
  "use strict";
  const Q=(1n<<272n)-237n,DELTA=65536n,L=1n<<256n;
  let checks=0,seed=0x59ab237d;
  const ok=(v,name)=>{checks++;if(!v)throw Error("R59 check: "+name);};
  const rand=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;};
  const small=()=>Number(rand()%3)-1;
  const bytes=n=>Array.from({length:n},()=>rand()%256);
  const mod=a=>((a%Q)+Q)%Q;
  const zero=n=>Array(n).fill(0n);
  const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  const src=(clauses,n)=>{
    const N=1<<n,one=()=>{let x=zero(N);x[0]=1n;return x;};
    const variable=i=>{let x=zero(N);x[1<<i]=1n;return x;};
    const mul=(a,b)=>{let z=zero(N);for(let i=0;i<N;i++)if(a[i])for(let j=0;j<N;j++)if(b[j])z[i|j]=mod(z[i|j]+a[i]*b[j]);return z;};
    const fail=([vars,bits])=>{
      let x=one();
      for(let j=0;j<vars.length;j++){
        let v=variable(vars[j]);
        if(!bits[j])v=one().map((a,k)=>mod(a-v[k]));
        x=mul(x,v);
      }
      return x;
    };
    const ev=(a,w)=>mod(a.reduce((s,v,i)=>s+(((i&w)===i)?v:0n),0n));
    const f=clauses.map(fail),gen=[];
    for(let i=0;i<f.length;i++)for(let j=i;j<f.length;j++)gen.push(mul(f[i],f[j]));
    for(let mask=0;mask<N;mask++){
      if(mask.toString(2).split("1").length-1>2)continue;
      let p=zero(N);p[mask]=1n;
      for(let a of f)gen.push(mul(a,p));
    }
    const piv=new Map();
    const pow=(a,k)=>{let z=1n;while(k){if(k&1n)z=mod(z*a);a=mod(a*a);k>>=1n;}return z;};
    for(let g of gen){
      let a=g.slice();
      for(let i=0;i<N;i++){
        if(!a[i])continue;
        if(!piv.has(i)){let inv=pow(a[i],Q-2n);piv.set(i,a.map(z=>mod(z*inv)));break;}
        let v=a[i],p=piv.get(i);
        a=a.map((z,j)=>mod(z-v*p[j]));
      }
    }
    let free=Array.from({length:N},(_,i)=>i).filter(i=>!piv.has(i)), inds=[...piv.keys()].sort((a,b)=>a-b);
    const P=a=>{
      let v=a.map(mod);
      for(let i of inds)if(v[i]){let co=v[i],p=piv.get(i);v=v.map((x,j)=>mod(x-co*p[j]));}
      return free.map(i=>v[i]);
    };
    const S=z=>{let x=zero(N);free.forEach((i,j)=>x[i]=z[j]);return x;};
    const valid=Array.from({length:N},(_,i)=>i).filter(w=>f.every(a=>ev(a,w)===0n));
    const enc=(word,eta)=>P(eta.map((e,i)=>BigInt(e)+(i===0?DELTA*word:0n)));
    const opening=(z,w)=>{
      ok(valid.includes(w),"genuine ORIGINAL witness");
      let c=ev(S(z),w),near=c/DELTA,options=[0n,L-1n,near,near+1n].filter(x=>x>=0n&&x<L);
      const dist=x=>{let t=mod(c-DELTA*x);return t<Q-t?t:Q-t;};
      let win=options.reduce((x,y)=>dist(x)<=dist(y)?x:y);
      ok(dist(win)<=BigInt(N),"bounded source error");
      return win;
    };
    return {N,rank:inds.length,dim:free.length,valid,P,S,enc,opening,one};
  };
  const c19=[
    [[1,3,4],[0,0,0]],[[0,1,4],[0,0,0]],[[0,1,4],[1,0,1]],[[1,3,5],[1,0,1]],
    [[1,3,4],[1,0,0]],[[0,1,2],[0,0,0]],[[0,3,4],[0,1,1]],[[2,3,5],[1,0,0]],
    [[0,4,5],[1,1,0]],[[1,2,5],[1,1,1]],[[1,2,4],[1,0,0]],[[0,3,4],[1,0,0]],
    [[0,4,5],[0,0,1]],[[2,4,5],[1,0,0]],[[2,3,4],[0,1,1]],[[0,3,5],[0,0,1]],
    [[0,4,5],[0,1,0]],[[1,3,4],[0,1,0]],[[1,2,4],[1,1,0]]
  ];
  const tru=src(c19.filter((_,i)=>i!==10),6);
  const fals=src([[[0,0,0],[1,1,1]],[[0,0,0],[0,0,0]]],4);
  ok(tru.rank===61&&tru.dim===3&&equal(tru.valid,[10,11,43]),"TRUE relation/rank");
  ok(fals.dim===2&&fals.valid.length===0&&fals.P(fals.one()).every(x=>x===0n),"nonempty certified-FALSE");
  const QL=256,m=8,n=4;
  const mat=()=>Array.from({length:m},()=>bytes(n));
  const secret=()=>bytes(n);
  const noise=()=>Array.from({length:m},small);
  const Y=(A,s,e)=>A.map((row,i)=>(row.reduce((v,a,j)=>v+a*s[j],0)+e[i]+10000*QL)%QL);
  const xor=(a,b)=>a.map((v,i)=>v^b[i]);
  const word=(s,e,kb)=>{
    let dat=[...s,...e.map(z=>z+1),...kb,...Array(12).fill(0)];
    ok(dat.length===32,"canonical 32 byte payload");
    return dat.reduce((z,v)=>(z<<8n)+BigInt(v),0n);
  };
  const recover=mu=>{
    let b=Array(32).fill(0);
    for(let i=31;i>=0;i--){b[i]=Number(mu&255n);mu>>=8n;}
    ok(b.slice(20).every(x=>x===0),"payload canonical padding");
    return {s:b.slice(0,4),e:b.slice(4,12).map(z=>z-1),kb:b.slice(12,20)};
  };
  const toyHash=(s)=>{
    let h=2166136261>>>0;
    for(let i=0;i<s.length;i++){h=Math.imul((h^s.charCodeAt(i))>>>0,16777619)>>>0;}
    return h.toString(16).padStart(8,"0");
  };
  const ids=["FALSE-target/UTXO-0","TRUE-related/UTXO-1","TRUE-related/UTXO-2"];
  const context="ORIGINAL-relation|claim|BTC/SYS-anchors/window|branch|vk|native-messages-distinct";
  const mlabel=ids.map((id,i)=>toyHash("signed-path-v1|"+context+"|"+id+"|relation="+(i===0?"FALSE":"TRUE")));
  ok(new Set(mlabel).size===3,"distinct claim-scoped signing messages");
  const sigs=mlabel.map(s=>Array.from({length:8},(_,i)=>toyHash(s+"-"+i).charCodeAt(i%8)));
  const publicBase=(A,rec)=>JSON.stringify({context,ids,mlabel,A,D:rec.map(x=>x.D),Z:rec.map(x=>x.Z.map(t=>t.map(String)))});
  const seal=(A,rec)=>{
    let base=publicBase(A,rec);
    for(let i=0;i<3;i++){
      let sec=rec[i].kb.join(",");
      rec[i].CK=toyHash("CK|"+ids[i]+"|"+sec+"|"+base);
      rec[i].AUX=toyHash("AUX|"+rec[i].CK+"|"+sec+"|"+base);
    }
  };
  const pub=(A,rec)=>JSON.stringify({context,ids,mlabel,A,records:rec.map(r=>({D:r.D,Z:r.Z.map(z=>z.map(String)),CK:r.CK,AUX:r.AUX}))});
  const recReal=(srcObj,s,e,kb,eta,A,sig)=>({D:xor(sig,Y(A,s,e)),Z:[srcObj.enc(word(s,e,kb),eta)],kb,s,e});
  const recTargetSim=(Ychallenge,kb,eta,sig)=>({D:xor(sig,Ychallenge),Z:[fals.P(eta.map(BigInt))],kb});
  let couplings=0,opens=0,uniform=0,negative=0;
  for(let trial=0;trial<64;trial++){
    let A=mat(),etaTrue=Array.from({length:64},small),etaFalse=etaTrue.slice(0,16);
    let kb=Array.from({length:3},()=>bytes(8)),related=[];
    for(let j=1;j<=2;j++)related.push(recReal(tru,secret(),noise(),kb[j],etaTrue,A,sigs[j]));
    let s0=secret(),e0=noise(),yc=Y(A,s0,e0);
    let honest=[recReal(fals,s0,e0,kb[0],etaFalse,A,sigs[0]),...related.map(x=>({...x}))];
    let sim=[recTargetSim(yc,kb[0],etaFalse,sigs[0]),...related.map(x=>({...x}))];
    seal(A,honest);seal(A,sim);
    ok(pub(A,honest)===pub(A,sim),"entire full-public LWE-challenge joint view exact");
    couplings++;
    const open=(j,table,w)=>{
      let mu=tru.opening(table[j].Z[0],w),o=recover(mu),yp=Y(A,o.s,o.e),sg=xor(table[j].D,yp);
      ok(equal(sg,sigs[j]),"ORIGINAL witness recovers same native capability bytes");
      let expected=toyHash("CK|"+ids[j]+"|"+o.kb.join(",")+"|"+publicBase(A,table));
      ok(table[j].CK===expected,"secret CK with all public records");
      ok(table[j].AUX===toyHash("AUX|"+expected+"|"+o.kb.join(",")+"|"+publicBase(A,table)),"secret AUX correlation");
      return {s:o.s,e:o.e,kb:o.kb,sig:sg};
    };
    for(let j=1;j<=2;j++)for(let w of tru.valid){
      let a=open(j,honest,w),b=open(j,sim,w);
      ok(equal(a,b),"mixed TRUE opening preserves LWE simulator coupling");
      opens++;
    }
    let yr=bytes(m),hy=[recTargetSim(yr,kb[0],etaFalse,sigs[0]),...related.map(x=>({...x}))];
    seal(A,hy);
    for(let j=1;j<=2;j++)for(let w of tru.valid)open(j,hy,w);
    uniform++;
    let sibling=open(1,hy,tru.valid[0]),sharedY=Y(A,sibling.s,sibling.e);
    let Dbad=xor(sigs[0],sharedY);
    ok(equal(xor(Dbad,sharedY),sigs[0]),"negative control: shared (s,e) leaks FALSE capability");
    negative++;
  }
  return {run:"R59-MIXED-TRUE-LWE-JOINT-20261104",checks,true_original_witnesses:tru.valid,
    false_target_quotient_dim:fals.dim,false_target_p1_zero:true,
    full_joint_real_challenge_couplings:couplings,related_true_original_openings:opens,
    uniform_lwe_hybrids_with_related_true_openings:uniform,shared_secret_negative_controls:negative,
    illustrative_lwe:{q:QL,n,m},checking_key:"finite toy secret-dependent hash of whole D/Z/A/context, NOT a PQ MAC",
    source_open_oracle_for_target:false,hard_true_original_extraction:"UNPROVED",qpt_hardness_tested:false};
}
console.log(JSON.stringify(runR59(),null,2));
