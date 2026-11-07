const r34Check = function r34Check(){
  let checks=0;
  const assert=(b,msg)=>{checks++;if(!b)throw Error(msg)};
  const binom=(n,k)=>{if(k>n)return 0;let a=1;for(let j=1;j<=k;j++)a=a*(n-j+1)/j;return Math.round(a)};
  const prime=n=>{const isP=k=>{if(k<2)return false;if(k%2===0)return k===2;for(let j=3;j*j<=k;j+=2)if(k%j===0)return false;return true};while(!isP(n))n++;return n};
  const ell=256,scopes=2,branches=3,lambda=128,eta=1;
  const parameters=[];
  for(const n of [11,20,30,50]){
    const M=Array.from({length:Math.min(6,n)+1},(_,j)=>binom(n,j)).reduce((a,b)=>a+b,0);
    const L=(lambda+n)*Math.LN2+Math.log(2*ell*scopes*branches);
    const q=prime(Math.ceil(4*eta*Math.sqrt(2*M*L)+1));
    const qold=prime(4*M*eta+2);
    const boundLog2=Math.log2(2*ell*scopes*branches)+n-((q-1)/4)**2/(2*M*eta**2*Math.LN2);
    assert(boundLog2<=-lambda,"failure bound");
    assert(M*eta<(qold-1)/4,"deterministic bound");
    assert(q<qold,"improvement");
    parameters.push({n,M,qDeterministic:qold,qCentered:q,ratio:Number((qold/q).toFixed(3)),failureUpperLog2:Number(boundLog2.toFixed(4))});
  }
  let seed=0x12a4b9;
  const rand=()=>{seed=(Math.imul(1664525,seed)+1013904223)>>>0;return seed};
  const nextBit=()=>((rand()>>>16)&1);
  const mod=(x,q)=>((x%q)+q)%q;
  const N=6,q=127,delta=63,dim=1<<N;
  const f0=Array(dim).fill(0),f1=Array(dim).fill(0),f2=Array(dim).fill(0),f3=Array(dim).fill(0);
  f0[7]=1;f1[24]=1;f1[28]=-1;f2[34]=1;f2[50]=-1;
  f3[32]=1;f3[33]=-1;f3[48]=-1;f3[49]=1;
  const fs=[f0,f1,f2,f3];
  const evalP=(p,z)=>{let a=0;for(let m=0;m<dim;m++)if((m&z)===m)a+=p[m];return mod(a,q)};
  const valid=Array.from({length:dim},(_,i)=>i).filter(z=>fs.every(f=>evalP(f,z)===0));
  assert(valid.length>=2&&valid.length<dim,"valid original assignments");
  const mix=c=>fs.reduce((p,f,j)=>{for(let i=0;i<dim;i++)p[i]=mod(p[i]+c[j]*f[i],q);return p},Array(dim).fill(0));
  const mul=(a,b)=>{const o=Array(dim).fill(0);for(let i=0;i<dim;i++)if(a[i])for(let j=0;j<dim;j++)if(b[j])o[i|j]=mod(o[i|j]+a[i]*b[j],q);return o};
  const circdist=(x,y)=>Math.min(mod(x-y,q),mod(y-x,q));
  let recoveries=0,bitCases=0;
  for(let trial=0;trial<6;trial++)for(let b=0;b<24;b++){
    const bit=nextBit();
    const e=Array.from({length:dim},()=>nextBit()?1:-1);
    const c=e.map(v=>mod(v,q));c[0]=mod(c[0]+delta*bit,q);
    for(let t=0;t<3;t++){
      const u=mix(Array.from({length:fs.length},()=>rand()%q));
      const v=mix(Array.from({length:fs.length},()=>rand()%q));
      const w=mul(u,v);
      for(let m=0;m<dim;m++)c[m]=mod(c[m]+w[m],q);
    }
    for(const z of valid){
      const raw=e.reduce((s,em,m)=>s+((m&z)===m?em:0),0);
      const got=evalP(c,z);
      assert(got===mod(delta*bit+raw,q),"honest release algebra");
      assert(Math.abs(raw)<(q-1)/4,"trial noise tail");
      const dec=Number(circdist(got,delta)<circdist(got,0));
      assert(dec===bit,"all-witness bit correctness");
      recoveries++;
    }
    bitCases++;
  }
  const idx=(a,b)=>mod(a,3)*3+mod(b,3);
  const prod=Array(9).fill(0);
  for(let r0=0;r0<3;r0++)for(let r1=0;r1<3;r1++)for(let s0=0;s0<3;s0++)for(let s1=0;s1<3;s1++)prod[idx(r1*s1,r0*s0)]++;
  assert(prod.reduce((a,b)=>a+b,0)===81,"product distribution");
  const conv=(a,b)=>{const out=Array(9).fill(0);for(let u=0;u<9;u++)for(let v=0;v<9;v++)out[idx(Math.floor(u/3)+Math.floor(v/3),u%3+v%3)]+=a[u]*b[v];return out};
  const d=conv(prod,prod);
  const shifted=a=>{const out=Array(9).fill(0);for(let x=0;x<3;x++)for(let y=0;y<3;y++)out[idx(x+1,y+1)]=a[idx(x,y)];return out};
  const tv=(a,b)=>a.reduce((s,v,i)=>s+Math.abs(v-b[i]),0)/(2*a.reduce((s,v)=>s+v,0));
  const noise=Array(9).fill(0);
  for(const a of [-1,1])for(const b of [-1,1])noise[idx(a,a+b)]++;
  assert(noise.reduce((a,b)=>a+b,0)===4,"noise distribution");
  const before=tv(d,shifted(d)),after=tv(conv(d,noise),conv(shifted(d),noise));
  assert(after<=before+1e-12,"convolution/data processing");
  return {status:"PASS",checks,release:{q,variables:N,clauses:fs.length,validAssignments:valid.length,bits:bitCases,simultaneousWitnessBitRecoveries:recoveries},convolution:{modulus:3,t:2,tvBefore:before,tvAfter:after},parameters,provenance:"offline deterministic V8 finite algebra; not PQ hardness"};
};
console.log(JSON.stringify(r34Check(), null, 2));
