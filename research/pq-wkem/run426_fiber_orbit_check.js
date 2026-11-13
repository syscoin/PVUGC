
let checks=0;
function yes(p,s){checks++;if(!p)throw Error(s);}
function factorial(n){let x=1;for(let i=2;i<=n;i++)x*=i;return x}
function perms(items){if(items.length===0)return [[]];let out=[];for(let i=0;i<items.length;i++)for(const tail of perms(items.filter((_,j)=>j!==i)))out.push([items[i],...tail]);return out}
function range(n){return Array.from({length:n},(_,i)=>i)}
function profile(f,m){let c=Array(m).fill(0);for(const z of f)c[z]++;return c.sort((a,b)=>b-a).join(",")}
function orbitSize(p,n,m){const ct=new Map();for(const r of p.split(",").map(Number))ct.set(r,1+(ct.get(r)||0));let den=1;for(const [r,a] of ct)den*=Math.pow(factorial(r),a)*factorial(a);return factorial(n)*factorial(m)/den}
function mapped(f,u,v){const g=Array(f.length);for(let x=0;x<f.length;x++)g[u[x]]=v[f[x]];return g}
function equalMaps(a,b){if(a.size!==b.size)return false;for(const [k,v] of a)if(b.get(k)!==v)return false;return true}
function mapFamily(n,m){let out=[],max=Math.pow(m,n);for(let c=0;c<max;c++){let v=c,f=[];for(let i=0;i<n;i++){f.push(v%m);v=Math.floor(v/m)}out.push(f)}return out}
const reports=[];
for(const [n,m] of [[3,3],[4,3],[4,4]]){
 const source=mapFamily(n,m),inputs=perms(range(n)),outputs=perms(range(m));
 const representatives=new Map(),classSizes={};
 const sampleCount=factorial(n)*factorial(m);
 for(const f of source){
  const p=profile(f,m),hist=new Map();
  for(const u of inputs)for(const v of outputs){
   const g=mapped(f,u,v),key=g.join(",");
   hist.set(key,(hist.get(key)||0)+1);
   yes(profile(g,m)===p,"fiber invariant");
  }
  const orbit=orbitSize(p,n,m);
  yes(hist.size===orbit,"orbit count");
  for(const v of hist.values())yes(v===sampleCount/orbit,"uniform orbit");
  if(representatives.has(p))yes(equalMaps(hist,representatives.get(p)),"same profile law");
  else representatives.set(p,hist);
 }
 const pairs=Array.from(representatives.entries());
 for(let i=0;i<pairs.length;i++)for(let j=i+1;j<pairs.length;j++){
  for(const k of pairs[i][1].keys())yes(!pairs[j][1].has(k),"different classes disjoint")
 }
 let coverage=0;
 for(const [p,hist] of representatives){classSizes[p]=hist.size;coverage+=hist.size}
 yes(coverage===Math.pow(m,n),"full class coverage");
 reports.push({n,m,source_functions:source.length,mask_pairs_per_source:sampleCount,classes:classSizes});
}
let lifts=0;
for(const n of [2,3,4])for(const m of [2,4]){
 for(const f of mapFamily(n,m)){
  const seen=new Set();
  for(let x=0;x<n;x++)for(let z=0;z<m;z++){
   const z2=z^f[x],k=x+":"+z2;
   yes(z2>=0&&z2<m,"xor output range");
   yes(!seen.has(k),"reversible injection");
   yes((z2^f[x])===z,"lift involution");seen.add(k)
  }
  yes(seen.size===n*m,"reversible bijection");
  lifts++;
 }
}
let leaked=0;
const p0=[0,0,0,0],p1=[0,0,1,1];
for(const [bit,f] of [[0,p0],[1,p1]])for(const u of perms(range(4)))for(const v of perms(range(4))){
 const g=mapped(f,u,v);
 const decoded=+(profile(g,4)===profile(p1,4));
 yes(decoded===bit,"secret bit recovered without input/output masks");
 leaked++;
}
return JSON.stringify({
 run:426,status:"all finite assertions passed",
 assertions:checks,exhaustive_orbits:reports,
 reversible_lift_source_maps:lifts,
 secret_bit_no_pin_mask_pairs:leaked,
 security_claim:"none; exact finite orbit theorem only",
 quantum:"classical attack, therefore available to QPT",
 native_signatures:"separate local Python checker tests 12 non-PQ Ed25519 cases",
 complete_practical_wkem:false
},null,2)+"\n";
