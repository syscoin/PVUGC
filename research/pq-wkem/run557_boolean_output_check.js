const check557 = function check557(){
 let checks=0; const ck=(x,m)=>{if(!x)throw Error(m);checks++};
 const pc=x=>{let k=0;while(x){k^=1;x&=x-1}return k};
 const fwht=ar=>{let a=ar.slice(),N=a.length;for(let s=1;s<N;s*=2)for(let i=0;i<N;i+=2*s)for(let j=i;j<i+s;j++){let x=a[j],y=a[j+s];a[j]=x+y;a[j+s]=x-y}return a};
 const gen=(n,seed)=>{let x=(0x6d2b79f5^(n*1009)^(seed*8191))>>>0;return Array.from({length:1<<n},()=>{x^=x<<13;x^=x>>>17;x^=x<<5;x>>>=0;return (x>>>24)&1?1:-1})};
 const rank=(vv)=>{let b={};for(let v of vv){while(v){let p=31-Math.clz32(v);if(b[p]!==undefined)v^=b[p];else{b[p]=v;break}}}return Object.keys(b).length};
 const next=(state)=>{let x=state.v;x^=x<<13;x^=x>>>17;x^=x<<5;state.v=x>>>0;return state.v};
 let rows=[];
 for(let n=7;n<=10;n++)for(let seed of [3,11]){
  let N=1<<n,h=gen(n,seed),W=fwht(h),cor=fwht(W.map(v=>v*v)).map(v=>v/N);
  ck(W.reduce((s,v)=>s+v*v,0)==N*N,'Parseval');
  let wt=W.map((v,t)=>(t?0:N*N)+v*v);
  ck(wt.reduce((s,v)=>s+v,0)==2*N*N,'normalization');
  let cmax=0;
  for(let d=1;d<N;d++){
   let same=(N+cor[d])/2;ck(Number.isInteger(same),'integer corr');cmax=Math.max(cmax,same/N);
   let bias=wt.reduce((s,v,t)=>s+((pc(t&d)?-1:1)*v),0);
   ck(bias==2*N*same,'exact Fourier translation law');
  }
  ck(cmax<.75,'unusually high autocorrelation');
  let T=Math.ceil(Math.log((N-1)/1e-6)/Math.log(8/7));
  let shifts=[1,N-1,Math.floor(N/3)],rr={v:(seed*23456789+n*777+1)>>>0};
  for(let D of shifts){
   let obs=[];
   for(let k=0;k<T;k++){
    let r=next(rr)%(2*N*N),t=0;
    for(;t<N;t++){r-=wt[t];if(r<0)break}
    ck(t<N,'sampling');obs.push([pc(t&D),t]);ck(pc(t&D)===obs[k][0],'parity equation');
   }
   ck(rank(obs.map(v=>v[1]))==n,'full rank recovered');
   let match=0,last=-1;
   for(let candidate=0;candidate<N;candidate++)if(obs.every(([b,t])=>pc(t&candidate)==b)){match++;last=candidate}
   ck(match==1&&last==D,'unique hidden shift');
  }
  rows.push({n,seed,cmax,zero_mass:wt[0]/(2*N*N),T,shifts:shifts.length});
 }
 for(let n=2;n<=5;n++){
  let N=1<<n,h=gen(n,23),W=fwht(h),D=N-1;
  for(let y=0;y<2*N;y++){
   let out=[0,0],t=y&(N-1),b=y>>>n;
   for(let branch=0;branch<2;branch++)for(let z=0;z<N;z++){
    let outbit=h[z^(branch?D:0)]===1?1:0;
    out[outbit]+=pc(t&z)^(b&branch)?-1:1;
   }
   let val=out[0]*out[0]+out[1]*out[1];
   let want=(b===pc(t&D))?2*((t?0:N*N)+W[t]*W[t]):0;
   ck(val===want,'direct coherent amplitude test');
  }
 }
 return {run:557,status:"PASS",assertions:checks,configs:rows.length,quantum_hardware:false,exact_formula:"Pr[t]=(N^2*1[t=0]+W_h(t)^2)/(2*N^2)",rows};
};
console.log(JSON.stringify(check557(), null, 2));
