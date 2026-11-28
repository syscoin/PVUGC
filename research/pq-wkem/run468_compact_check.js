// Run 468, deterministic finite graph-Fourier diagnostic. No quantum hardware.
function checkRun() {
  let assertions=0;
  const ok=(x,msg)=>{assertions++;if(!x)throw Error(msg)};
  const parity=x=>{let p=0;while(x){p^=1;x&=x-1}return p};
  const result=[];
  for(const [n,initial] of [[4,46801],[6,46802]]) {
    const r=n/2,size=1<<n,mask=(1<<r)-1,N=1+n+r;
    let seed=initial>>>0;
    const next=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};
    const shuffle=a=>{for(let i=a.length-1;i>0;i--){let j=next()%(i+1);[a[i],a[j]]=[a[j],a[i]]}return a};
    let P,f,maximum;
    do {
      P=shuffle(Array.from({length:size},(_,i)=>i));
      f=P.map(v=>v>>>r);
      maximum=0;
      for(let d=1;d<size;d++) {
        const count=Array(1<<r).fill(0);
        for(let z=0;z<size;z++)count[f[z]^f[z^d]]++;
        maximum=Math.max(maximum,...count);
      }
    } while(maximum===size);
    const delta=1+next()%(size-1);
    const perms=Array.from({length:1<<r},()=>shuffle(Array.from({length:1<<r},(_,i)=>i)));
    const L=y=>((y>>>r)<<r)|perms[y>>>r][y&mask];
    const F=(b,z)=>b?L(P[z^delta]):P[z];
    const g=(b,z)=>F(b,z)>>>r;
    for(let z=0;z<size;z++)ok(g(1,z)===g(0,z^delta),'paired projection');
    for(let y=0;y<size;y++)ok((L(y)>>>r)===(y>>>r),'relabel invariant');
    ok(new Set(Array.from({length:size},(_,i)=>L(i)^i)).size>1,'nonconstant output mask');
    ok(Array.from({length:size},(_,u)=>u).some(u=>Array.from({length:size},(_,v)=>v).some(v=>(L(u^v)^L(0))!==(L(u)^L(v)))),'nonaffine relabel');
    const graph=Array(1<<N).fill(0);
    for(let b=0;b<2;b++)for(let z=0;z<size;z++)graph[(b<<(n+r))|(z<<r)|g(b,z)]=1;
    const secret=(1<<(n+r))|(delta<<r);
    for(let i=0;i<graph.length;i++)if(graph[i])ok(graph[i^secret]===1,'graph symmetry');
    for(let h=1;h<graph.length;h*=2)for(let start=0;start<graph.length;start+=2*h)
      for(let j=start;j<start+h;j++){let a=graph[j],b=graph[j+h];graph[j]=a+b;graph[j+h]=a-b}
    const weights=graph.map(v=>v*v);
    const total=weights.reduce((a,b)=>a+b,0);
    ok(total===(1<<(n+1))*(1<<N),'Parseval');
    for(let y=0;y<weights.length;y++)if(parity(y&secret))ok(weights[y]===0,'Fourier annihilator');
    for(let v=0;v<1<<N;v++) {
      let c=(v>>>(n+r))&1,d=(v>>>r)&(size-1),e=v&mask,t=d^(c?delta:0);
      const hits=Array.from({length:size},(_,z)=>z).filter(z=>(f[z]^f[z^t])===e).length;
      if(v!==0&&v!==secret)ok(hits<=maximum,'differential bound');
      const moment=weights.reduce((s,w,y)=>s+(parity(v&y)?-w:w),0);
      ok(moment*size===hits*total,'exact Walsh overlap');
    }
    let gamma=(1+maximum/size)/2;
    let q=Math.ceil((N+18)/Math.log2(1/gamma));
    ok((2**N-2)*gamma**q<2**-14,'union bound');
    let cumulative=[],sum=0;
    for(const w of weights){sum+=w;cumulative.push(sum)}
    const rows=[];
    for(let j=0;j<q;j++){
      const k=next()%total;let lo=0,hi=cumulative.length-1;
      while(lo<hi){const m=(lo+hi)>>1;if(cumulative[m]>k)hi=m;else lo=m+1}
      rows.push(lo);
    }
    const basis={};
    for(const row of rows){let v=row;while(v){let pivot=31-Math.clz32(v);if(basis[pivot]===undefined){basis[pivot]=v;break}v^=basis[pivot]}}
    const pivots=Object.keys(basis).map(Number);
    ok(pivots.length===N-1,'sample rank');
    const free=Array.from({length:N},(_,j)=>j).find(j=>basis[j]===undefined);
    let recovered=1<<free;
    for(const pivot of pivots.sort((a,b)=>a-b))if(parity(basis[pivot]&recovered))recovered^=1<<pivot;
    ok(recovered===secret,'recover input shift');
    result.push({n,r,dimension:N,differential_max:String(maximum)+"/"+String(size),samples:q,recovered:true});
  }
  return {run:468,status:'PASS',assertions,fixtures:result,claim:'Finite exact diagnostic only; no obfuscator/PQ WKEM/QPU'};
}
if(typeof console !== 'undefined')console.log(JSON.stringify(checkRun(),null,2));
