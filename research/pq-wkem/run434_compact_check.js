#!/usr/bin/env node
const result = (function run434Compact(){
  let checks=0;
  function ok(v,msg){checks++;if(!v)throw Error(msg)}
  function parity(a,b){let k=a&b,v=0;while(k){v^=1;k&=k-1}return v}
  function audit(n,k,seed){
    let state=seed|0;
    function rnd(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0}
    let N=1<<n,s=1+rnd()%(N-1),L=Array.from({length:N},(_,i)=>i);
    for(let i=N-1;i>0;i--){const j=rnd()%(i+1);[L[i],L[j]]=[L[j],L[i]]}
    const F=L.map((_,z)=>{let a=L[z],b=L[z^s];return a<b?`${a}:${b}`:`${b}:${a}`});
    const G=F.slice(),points=new Set();
    while(points.size<k)points.add(rnd()%N);
    for(let z of points)G[z]=`patched-${z}`;
    function spectrum(fn){
      const fibers=new Map();
      for(let z=0;z<N;z++){let g=fn[z];if(!fibers.has(g))fibers.set(g,[]);fibers.get(g).push(z)}
      const p=[];
      for(let y=0;y<N;y++){
        let v=0;
        for(let fiber of fibers.values()){
          let a=0;for(let z of fiber)a+=parity(y,z)?-1:1;
          v+=a*a;
        }
        p.push(v);
      }
      ok(p.reduce((a,b)=>a+b,0)===N*N,"probability normalization");
      return p;
    }
    const p=spectrum(G),p0=spectrum(F);
    for(let y=0;y<N;y++)ok(p0[y]===(parity(y,s)?0:2*N),"ideal Fourier support and uniformity");
    let bad=0,dis=0,tvsum=0;
    for(let y=0;y<N;y++){if(parity(y,s))bad+=p[y];tvsum+=Math.abs(p[y]-p0[y])}
    for(let z=0;z<N;z++)if(G[z]!==G[z^s])dis++;
    ok(2*bad===dis*N,"exact p_bad=eta/2");
    ok(bad<=k*N,"fraction patched bound");
    let delta=k/N,tv=tvsum/(2*N*N);
    ok(tv*tv<=2*delta-delta*delta+1e-12,"trace distance bounds TV");
    for(let t=1;t<N;t++)if(t!==s){
      let agrees=0;for(let z=0;z<N;z++)if(G[z]===G[z^t])agrees++;
      ok(agrees<=2*k,"false period cannot retain more than 2k agreements");
    }
    return {n,period:s,patch_count:k,patch_fraction:`${k}/${N}`,bad_fourier_numerator:bad,bad_fourier_denominator:N*N,disagreement_count:dis,total_variation:tv};
  }
  const cases=[[4,0,1],[5,1,3],[6,2,9],[8,1,17],[8,2,21]].map(v=>audit(...v));
  return {run:434,checker:"exact finite Fourier spectrum, not quantum hardware",assertions_passed:checks,cases,complete_pq_wkem:false};
})();
process.stdout.write(JSON.stringify(result,null,2)+'\n');
