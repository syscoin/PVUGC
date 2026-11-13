'use strict';
// Independent S3 enumeration of a four-vertex diamond's publicly masked transitions.
const ps=[];
for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)if(new Set([a,b,c]).size===3)ps.push([a,b,c]);
const id=[0,1,2], s=[1,0,2], q=[0,2,1];
const mul=(a,b)=>b.map(i=>a[i]);
const inv=a=>[a.indexOf(0),a.indexOf(1),a.indexOf(2)];
const encode=(g,secret)=>{
 const t=secret?s:id, branch2=secret?mul(s,q):id;
 const Ts=[id,t,id,branch2];
 const uv=[[0,1],[1,3],[0,2],[2,3]];
 return uv.map(([u,v],i)=>mul(mul(g[v],Ts[i]),inv(g[u])));
};
const key=a=>a.map(v=>v.join('')).join(':');
const maps=[new Map(),new Map()];
let checks=0;
for(let b=0;b<=1;b++)for(const a of ps)for(const c of ps)for(const d of ps)for(const e of ps){
  const g=[a,c,d,e], x=encode(g,b);
  const p0=mul(x[1],x[0]), p1=mul(x[3],x[2]);
  if(p0[g[0][0]]!==g[3][b] || p1[g[0][0]]!==g[3][b])throw Error('semantic mismatch');
  const hol=mul(p1,inv(p0));
  const isId=hol.every((v,i)=>v===i);
  if(isId!==(b===0))throw Error('wrong relative cycle');
  const k=key(x);maps[b].set(k,(maps[b].get(k)||0)+1);checks+=2;
}
if([...maps[0].keys()].some(k=>maps[1].has(k)))throw Error('full-view supports overlap');
if(maps[0].size!==216 || maps[1].size!==648)throw Error('support size');
if([...maps[0].values()].some(n=>n!==6)||[...maps[1].values()].some(n=>n!==2))throw Error('multiplicity');
const asProjection=(m,omit)=>{const d=new Map();for(const [k,n] of m){const ss=k.split(':');ss.splice(omit,1);const kk=ss.join(':');d.set(kk,(d.get(kk)||0)+n);}return d;};
for(let i=0;i<4;i++){
 const u=asProjection(maps[0],i),v=asProjection(maps[1],i);
 if(u.size!==216||v.size!==216)throw Error('projection support');
 for(const [k,n] of u)if(n!==6||v.get(k)!==n)throw Error('projection mismatch');
 checks++;
}
const out={run:547, independent_implementation:'nodejs', configurations_per_secret:Math.pow(6,4),full_support_sizes:[maps[0].size,maps[1].size],full_overlap:0,all_three_edge_views_identical:true,checks,status:'PASS'};
process.stdout.write(JSON.stringify(out,null,2)+'\n');
