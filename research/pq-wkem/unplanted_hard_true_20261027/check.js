function checkUnplantedSource(){
  let assertions=0;
  const ck=(x,msg)=>{if(!x)throw Error("assertion "+assertions+": "+(msg||""));assertions++};
  function subsets(a,k,start=0,acc=[],out=[]){
    if(acc.length===k){out.push(acc.slice());return out}
    for(let i=start;i<a.length;i++){acc.push(a[i]);subsets(a,k,i+1,acc,out);acc.pop()}
    return out;
  }
  const q0=3,n0=6,h0=3;
  const ss=subsets([1,2,3,4,5],h0-1);
  ck(ss.length===10);
  const cnt=Array(11).fill(0),single=Array(10).fill(0),pairs=Array.from({length:10},()=>Array(10).fill(0));
  for(let v=0;v<729;v++){
    let t=v;const B=[];
    for(let i=0;i<n0;i++){B.push(t%q0);t=Math.floor(t/q0)}
    const flags=ss.map(S=>(B[0]+S.reduce((a,i)=>a+B[i],0))%q0===0);
    const x=flags.filter(Boolean).length;cnt[x]++;
    for(let i=0;i<10;i++)if(flags[i]){
      single[i]++;
      for(let j=i+1;j<10;j++)if(flags[j])pairs[i][j]++;
    }
    ck(x>=0&&x<=10);
  }
  ck(cnt.reduce((a,b)=>a+b,0)===729);ck(cnt[0]===36);
  for(let i=0;i<10;i++){
    ck(single[i]===243);
    for(let j=i+1;j<10;j++)ck(pairs[i][j]===81);
  }
  ck(cnt.reduce((a,b,i)=>a+i*b,0)===2430);
  ck(cnt.reduce((a,b,i)=>a+i*i*b,0)===9720);
  const choose=(n,k)=>{
    let v=1n;
    for(let i=1;i<=k;i++)v=v*BigInt(n-k+i)/BigInt(i);
    return v;
  };
  const N=choose(4499,2249),qd=65537n**256n;
  ck(N>qd*(2n**390n));
  const q=65537,h=2250,g=2*h+1,m=Math.floor(q/g);
  let size=1n,ell=0;
  while(size<2n**256n){size*=BigInt(m);ell++}
  ck(m===14&&ell===68&&size/BigInt(m)<2n**256n);
  ck(q-(m-1)*g>=g);
  ck((g/q)<0.07);
  let state=0x546c2a79;
  const rand=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state};
  const qt=101,nt=11,ht=5,gt=2*ht+1,mt=Math.floor(qt/gt);
  const options=subsets([1,2,3,4,5,6,7,8,9,10],4);
  let B,ws=[],attempt=0;
  for(attempt=1;attempt<=300;attempt++){
    const tmp=Array.from({length:nt},()=>rand()%qt);
    const v=options.filter(S=>(tmp[0]+S.reduce((a,i)=>a+tmp[i],0))%qt===0);
    if(v.length>=2){B=tmp;ws=v;break}
  }
  ck(B!==undefined&&ws.length>=2);
  const ncol=81;
  const distance=(a,b)=>{const z=((a-b)%qt+qt)%qt;return Math.min(z,qt-z)};
  const xor=(a,b)=>a.map((v,i)=>v^b[i]);
  const equal=(a,b)=>a.every((v,i)=>v===b[i]);
  const toBig=(bytes)=>bytes.reduce((a,v)=>(a<<8n)|BigInt(v),0n);
  const toBytes=(v)=>{let out=Array(32).fill(0);for(let i=31;i>=0;i--){out[i]=Number(v&255n);v>>=8n}ck(v===0n);return out};
  for(let trial=0;trial<12;trial++){
    const K=Array.from({length:32},()=>rand()%256),U=Array.from({length:32},()=>rand()%256),Z=Array.from({length:32},()=>rand()%256);
    const D=xor(U,Z),V=xor(K,U);
    let a=toBig(Z);const ts=[];
    for(let j=0;j<ncol;j++){ts.push(Number(a%BigInt(mt)));a/=BigInt(mt)}
    ck(a===0n);
    const cols=ts.map(t=>{
      const s=rand()%qt,err=Array.from({length:nt},()=>rand()%3-1);
      return B.map((b,i)=>(b*s+err[i]+(i===0?gt*t:0)+qt*qt)%qt);
    });
    for(const S of ws){
      const w=[0,...Array(10).fill(0)];w[0]=1;for(const i of S)w[i]=1;
      ck(w.reduce((a,b)=>a+b,0)===ht);
      ck(B.reduce((a,b,i)=>a+b*w[i],0)%qt===0);
      let zint=0n,scale=1n;
      for(const p of cols){
        const proj=p.reduce((a,v,i)=>a+v*w[i],0)%qt;
        const matches=[];
        for(let t=0;t<mt;t++)if(distance(proj,gt*t)<=ht)matches.push(t);
        ck(matches.length===1);
        zint+=BigInt(matches[0])*scale;scale*=BigInt(mt);
      }
      const recovered=xor(V,xor(D,toBytes(zint)));
      ck(equal(recovered,K));
    }
  }
  let aCount=0;
  for(let y=0;y<qt;y++)if(distance(y,0)<=ht)aCount++;
  ck(aCount===gt);
  return {status:"PASS",assertions,small:{matrices:729,candidate_witnesses:10,pairwise_pairs:45,false_probability:"4/81",Chebyshev_bound:"1/5"},large:{q,d:256,n:4500,h,delta_bound:"2^-390",m,columns:ell},toy:{unplanted_draws:attempt,valid_witnesses:ws.length,rounds:12,columns:ncol},note:"Algebraic checks only, not QPT or native-signature certification"};
}
console.log(JSON.stringify(checkUnplantedSource()));
