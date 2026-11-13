function run(){
const q=257,m=64,p=m+1,n=2*m+1,d=3,K=73;let seed=699064,assertions=0;
const rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};
const mod=x=>(x%q+q)%q;
const inv=x=>{let v=1;for(let j=0;j<q-2;j++)v=mod(v*x);return v};
const ok=(b,msg)=>{if(!b)throw Error(msg);assertions++};
const unit=j=>{const a=Array(p).fill(0);a[j]=1;return a};
const factors=[];
for(let i=0;i<m;i++){
 const L=[],R=[];
 for(let u=0;u<4;u++){
  const req=u===0?Array.from({length:n},(_,r)=>r).filter(r=>r===2*i||r===2*i+1||(i===0&&r===n-1)):[];
  const used=new Set(req);while(used.size<d)used.add(rnd()%n);
  L.push(new Map([...used].map(r=>[r,1+rnd()%(q-1)])));
 }
 for(let v=0;v<4;v++){
  const req=v===1?Array.from({length:n},(_,r)=>r).filter(r=>r===2*i||r===2*i+1||(i===0&&r===n-1)):[];
  const used=new Set(req);while(used.size<d)used.add(rnd()%n);
  R.push(new Map([...used].map(c=>[c,req.includes(c)?rnd()%q:1+rnd()%(q-1)])));
 }
 factors.push({L,R,X:Array.from({length:p},()=>rnd()%q)});
}
function make(shift=false, footprint=false){
 const M=new Map(),cnt=new Map();
 for(let i=0;i<m;i++){
 const {L,R,X}=factors[i],e=unit(i+1),z=unit(0),neg=X.map(x=>mod(-x));
 const terms=[[0,0,e],[0,1,z],[0,2,neg],[1,0,e],[1,1,e],[1,3,X],[2,2,e],[2,3,z],[3,2,e],[3,3,e]];
 for(const [u,v,vec] of terms)for(const [r,lv] of L[u])for(const [c,rv] of R[v]){
  if(!lv||!rv)continue;const key=r*n+c,scale=mod(lv*rv);
  const arr=M.get(key)||Array(p).fill(0);for(let j=0;j<p;j++)if(vec[j])arr[j]=mod(arr[j]+scale*vec[j]);M.set(key,arr);
  if(footprint)cnt.set(key,(cnt.get(key)||0)+1);
 }
 }
 if(shift)for(let r=0;r<n;r++){const key=r*n+r,a=M.get(key)||Array(p).fill(0);a[0]=mod(a[0]+K);M.set(key,a);if(footprint)cnt.set(key,(cnt.get(key)||0)+1)}
 return {M,cnt};
}
const base=make().M;
for(let r=0;r<n;r++){
 const i=r<n-1?Math.floor(r/2):0,{L,R}=factors[i];
 const alpha=L[0].get(r),old=R[1].get(r);
 ok(alpha!==undefined&&old!==undefined,"reserved");
 const a=base.get(r*n+r)||Array(p).fill(0);
 const B=mod(a[0]-alpha*old),bad=mod(-B*inv(alpha)),draw=rnd()%(q-1),fresh=draw+(draw>=bad);
 R[1].set(r,fresh);ok(mod(B+alpha*fresh)!==0,"covered");
}
const {M,cnt}=make(true,true);const unshift=make().M;
for(let r=0;r<n;r++)ok((unshift.get(r*n+r)||Array(p).fill(0))[0]!==0,"diagonal covered");
const seen=new Map(),dirs=[],entries=[];let unitCount=0;
for(const key of [...M.keys()].sort((a,b)=>a-b)){
 const v=M.get(key);let pivot=v.findIndex(x=>x!==0);if(pivot<0)continue;
 const alpha=v[pivot],ia=inv(alpha),u=v.map(x=>mod(x*ia)),sig=u.join(",");
 let idx=seen.get(sig);
 if(idx===undefined){idx=dirs.length;seen.set(sig,idx);dirs.push(u);if(u.filter(x=>x!==0).length===1)unitCount++}
 entries.push([key,alpha,idx]);}
const decoded=new Map();for(const [key,alpha,idx] of entries)decoded.set(key,dirs[idx].map(x=>mod(x*alpha)));
for(const [key,v] of M){const got=decoded.get(key)||Array(p).fill(0);ok(got.every((x,j)=>x===v[j]),"decoded public coefficient")}
for(let trial=0;trial<4;trial++){
 const z=[1,...Array.from({length:m},(_,i)=>(i*7+trial*11)%13<6?1:0)];
 const vals=dirs.map(u=>mod(u.reduce((s,x,j)=>s+x*z[j],0)));
 for(const [key,alpha,idx]of entries){
 const direct=mod(M.get(key).reduce((s,x,j)=>s+x*z[j],0));
 ok(mod(alpha*vals[idx])===direct,"evaluation exact");
 }
}
const E=[...cnt.values()].filter(x=>x>1).length,D=dirs.length,S=entries.length;
ok(D<=1+m*(1+1)+E,"direction lemma");
ok(S<=Math.min(n*n,n+m*(8+2)*d*d),"support lemma");
const bytesOld=S*p*32+S*8,bytesNew=S*(32+12)+D*4+(D-unitCount)*(p-1)*32;
const report={run:699,scope:"compact exact source-covered Run698-form direction codec regression; correctness only",q,m,p,n,d,K,assertions,S,D,unit_directions:unitCount,primitive_overlaps:E,old_bytes:bytesOld,projective_bytes:bytesNew,ratio:Number((bytesOld/bytesNew).toFixed(4)),eigenvalue_security:"NOT PROVEN",native_bitcoin_endpoint:"NOT TESTED"};
ok(bytesNew<bytesOld,"positive storage ratio");report.assertions=assertions;
return report;
}
console.log(JSON.stringify(run(),null,2));
