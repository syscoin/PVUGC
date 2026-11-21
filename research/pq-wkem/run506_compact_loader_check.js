'use strict';
const run = () => {
  let checks=0; const ok=(x,m)=>{checks++;if(!x)throw Error(m)};
  const rot=(w,n)=>((w>>>1)|((w&1)<<(n-1)))&((1<<n)-1);
  const word=(w,n)=>{const a=[];for(let j=0;j<n;j++){if((w>>>j)&1)a.push("X");a.push("R")}return a};
  const inv=(p)=>{const v=new Array(p.length);for(let i=0;i<p.length;i++)v[p[i]]=i;return v};
  const shifted=(p,n,delta)=>p.map((_,i)=>p[i^(delta<<n)]);
  const view=(p,n,k)=>{
    const v=inv(p), R=[],X=[],mask=(1<<n)-1;
    for(let y=0;y<p.length;y++){const i=v[y],s=i>>>n,w=i&mask;R.push(p[(s<<n)|rot(w,n)]);X.push(p[(s<<n)|(w^1)])}
    return {R,X,a:p[k<<n]};
  };
  const entry=(v,w,n)=>{let s=v.a;for(const c of word(w,n))s=v[c][s];return s};
  let words=0,unary=0,frames=0,randomFrames=0,invalid=0;
  for(let n=1;n<=10;n++){
    const size=1<<n;
    const seen=new Set();let state=0;
    for(let t=0;t<size;t++){ok(!seen.has(state),"cycle distinct");seen.add(state);state=(state+1)%size;unary++}
    ok(state===0&&seen.size===size,"unary cycle full");
    for(let w=0;w<size;w++){
      let got=0,count=0;
      for(const c of word(w,n)){got=c==="X"?(got^1):rot(got,n);count++}
      ok(got===w,"two-generator exact late input");
      ok(count<=2*n,"linear number of operations");words++;
    }
  }
  for(const n of [1,2]){
    const N=1<<(n+1),p=Array.from({length:N},(_,i)=>i);
    const recur=(j)=>{
      if(j===N){
        const alt=shifted(p,n,1),a=view(p,n,0),b=view(alt,n,1);
        ok(JSON.stringify(a)===JSON.stringify(b),"identical full public views");
        for(let w=0;w<(1<<n);w++){
          const y=entry(a,w,n);
          ok(y===p[w]&&y===alt[(1<<n)|w],"public late input and exact seed translation");
        }
        frames++;return;
      }
      for(let i=j;i<N;i++){[p[j],p[i]]=[p[i],p[j]];recur(j+1);[p[j],p[i]]=[p[i],p[j]]}
    };
    recur(0);
  }
  let seed=0x506F00D;const rnd=(max)=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%max};
  for(const [h,n] of [[1,3],[2,2],[2,3],[3,3]]){
    const N=1<<(h+n);
    for(let rep=0;rep<20;rep++){
      const p=Array.from({length:N},(_,i)=>i);
      for(let i=N-1;i>0;i--){const j=rnd(i+1);[p[i],p[j]]=[p[j],p[i]]}
      const k0=rnd(1<<h),k1=rnd(1<<h);
      const alt=shifted(p,n,k0^k1),v0=view(p,n,k0),v1=view(alt,n,k1);
      ok(JSON.stringify(v0)===JSON.stringify(v1),"general seed translation hides K");
      for(let w=0;w<(1<<n);w++){
        ok(entry(v0,w,n)===p[(k0<<n)|w],"any witness can be written publicly");
        invalid++; // false ORIGINAL relation: source validity is false for every w
      }
      randomFrames++;
    }
  }
  const identity=[...Array(1<<(2+3)).keys()],idView=view(identity,3,2);
  ok(idView.a>>>3===2,"malicious known frame exposes K");
  return {run:506,scope:"exponential ideal-frame loader only, NOT witness-KEM",checks,unaryOrbitStates:unary,loaderWords:words,exhaustiveFrameCouplings:frames,sampledFrameCouplings:randomFrames,falseSourceReachableStates:invalid,maliciousFrameLeak:true,status:"PASS"};
};
process.stdout.write(JSON.stringify(run(),null,2)+'\n');
