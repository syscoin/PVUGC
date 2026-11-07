const result = (function check() {
  let checks=0;
  const ck=(b,msg)=>{if(!b)throw Error("CHECK FAILURE "+msg);checks++};
  const signs=[[1,1],[1,-1],[-1,1],[-1,-1]], q=1009, D=8, g=48, m=6;
  const A=signs.map(([s,t],j)=>Array.from({length:m},(_,i)=>i===0?s:i===1?t:i===j+2?-1:0));
  const dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
  const matvec=(z)=>A.map(r=>dot(r,z));
  const original=(a,b)=>[2*a-1,2*b-1,...signs.map(([s,t])=>s*(2*a-1)+t*(2*b-1)-1)];
  const accepted=z=>z.every(x=>Math.abs(x)===1)&&matvec(z).every(x=>x===1);
  for(let a=0;a<2;a++)for(let b=0;b<2;b++){let z=original(a,b);ck(matvec(z).every(x=>x===1),"linear source");ck(!accepted(z),"four-clause UNSAT");ck(z.filter(x=>Math.abs(x)>1).length===1,"one illegal slack")}
  const zf=[0,0,-1,-1,-1,-1];ck(matvec(zf).every(x=>x===1),"false pseudo solution");ck(!accepted(zf),"not signed witness");
  let solutions=[];
  for(let n=0;n<729;n++){let w=n,z=[];for(let i=0;i<m;i++){z.push(w%3-1);w=Math.floor(w/3)}if(matvec(z).every(x=>x===1))solutions.push(z.join(","))}
  ck(solutions.length===1 && solutions[0]===zf.join(","),"unique small-cube pseudo");
  let worstFalse=0,worstSigned=0;
  for(let idx=0;idx<m;idx++)for(let s of [-1,1])for(let dense of [-1,1]){
    let e=Array(m).fill(dense);e[idx]+=s*D;
    let ef=dense-dot(zf,e); worstFalse=Math.max(worstFalse,Math.abs(ef));
    for(let t=0;t<64;t++){const z=Array.from({length:m},(_,i)=>(t>>i)&1?1:-1);
      worstSigned=Math.max(worstSigned,Math.abs(dense-dot(z,e)));
      ck(Math.abs(ef)<=Math.abs(dense)+e.reduce((p,x)=>p+Math.abs(x),0),"samplewise domination");
    }
  }
  ck(worstFalse<g/2 && worstSigned<g/2,"uniform decoding margin");
  let state=0x6ea4b2e5;
  const next=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0};
  const rand=n=>next()%n;
  const source=(cl)=>cl.map(([s,t],j)=>Array.from({length:2+cl.length},(_,i)=>i===0?s:i===1?t:i===j+2?-1:0));
  const trueCl=[[1,1],[-1,-1]],At=source(trueCl),Ut=[1,1],Uf=[1,1,1,1];
  const trueZ=[[1,-1,-1,-1],[-1,1,-1,-1]];
  trueZ.forEach(z=>ck(z.every(x=>Math.abs(x)===1)&&At.every((r,i)=>dot(r,z)===Ut[i]),"distinct true witness"));
  function capsule(M,U,bit){const nn=M.length,mm=M[0].length,r=Array.from({length:nn},()=>rand(q)),eta=Array.from({length:mm},()=>rand(3)-1),ed=rand(3)-1;
    eta[rand(mm)]+=rand(2)?D:-D;
    const c=Array.from({length:mm},(_,j)=>(M.reduce((v,row,i)=>v+row[j]*r[i],eta[j])%q+q)%q);
    const d=((dot(U,r)+ed+g*bit)%q+q)%q;
    return {c,d,eta,ed,r};
  }
  const dec=(cp,z)=>{let v=((cp.d-dot(z,cp.c))%q+q)%q;if(v>q/2)v-=q;return Math.abs(v-g)<Math.abs(v)?1:0};
  let trueChecks=0,falseChecks=0;
  for(let bit=0;bit<256;bit++){
    const k=rand(2);
    for(let capsuleId=0;capsuleId<2;capsuleId++){
      const tr=capsule(At,Ut,k),fl=capsule(A,Uf,k);
      for(let z of trueZ){ck(dec(tr,z)===k,"true same capability");trueChecks++}
      ck(dec(fl,zf)===k,"false native capability leak");
      let v=((fl.d-dot(zf,fl.c))%q+q)%q;if(v>q/2)v-=q;
      ck(v===g*k+fl.ed-dot(zf,fl.eta),"exact false residual");falseChecks++;
    }
  }
  for(let a=0;a<2;a++)for(let b=0;b<2;b++){
    const z=original(a,b),t=z.map(v=>(v-1)/2);
    ck(z.every((v,i)=>v-2*t[i]===1),"parity integral pseudo");
    ck(z.some(v=>Math.abs(v)>1),"parity not enough");
  }
  for(let t=-3;t<=3;t++)ck((q+(0-2*t-1)%q)%q!==0,"fractional no small parity t");
  return {status:"NO_POSITIVE_ADVANCE",run:"fractional_lp_spike_no_go_20261030",assertions:checks,sourceCubeCount:solutions.length,worstFalseNoise:worstFalse,worstValidNoise:worstSigned,spacing:g,trueChecks,falseChecks,relatedCapsules:2,q,spikeAmplitude:D};
})();
console.log(JSON.stringify(result,null,2));
