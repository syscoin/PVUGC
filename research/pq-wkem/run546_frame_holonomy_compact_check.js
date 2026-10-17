"use strict";
const ok=(p,m)=>{if(!p)throw new Error(m);};
let nchecks=0;
const perm=a=>a.length===0?[[]]:a.flatMap((v,i)=>perm(a.filter((_,j)=>i!==j)).map(p=>[v,...p]));
const G=perm([0,1,2,3]),I=[0,1,2,3];
const mul=(p,q)=>q.map(i=>p[i]);
const inv=p=>p.map((_,i)=>p.indexOf(i));
const swap=(i,j)=>{const p=I.slice();[p[i],p[j]]=[p[j],p[i]];return p;};
const cls=p=>{let v=[],seen=new Set();for(let i=0;i<p.length;i++){if(seen.has(i))continue;let j=i,t=0;do{seen.add(j);t++;j=p[j];}while(!seen.has(j));v.push(t);}return v.sort((a,b)=>b-a).join(",");};
const tab=(Ts,L,R)=>Ts.map(T=>mul(mul(L,T),R));
const dist=Ts=>{let m=new Map();for(const L of G)for(const R of G){const k=JSON.stringify(tab(Ts,L,R));m.set(k,(m.get(k)||0)+1);}return m;};
const proj=(d,idx)=>{const o=new Map();for(const [k,v] of d){const a=JSON.parse(k);const h=JSON.stringify(idx.map(i=>a[i]));o.set(h,(o.get(h)||0)+v);}return o;};
const same=(a,b)=>a.size===b.size&&[...a].every(([k,v])=>b.get(k)===v);
const c0=[I,swap(0,1),swap(2,3)],c1=[I,swap(0,1),swap(1,2)];
const D0=dist(c0),D1=dist(c1);
for(const ix of [[0],[1],[2],[0,1],[0,2]]){ok(same(proj(D0,ix),proj(D1,ix)),"marginal "+ix);nchecks++;}
ok(D0.size===144&&D1.size===576,"orbit count");nchecks++;
ok([...D0.values()].every(v=>v===4)&&[...D1.values()].every(v=>v===1),"weights");nchecks++;
for(const [d,want] of [[D0,"2,2"],[D1,"3,1"]])for(const [k] of d){const a=JSON.parse(k);ok(cls(mul(a[1],inv(a[2])))===want,"relative class");nchecks++;}
const pi=proj(D0,[1,2]),pj=proj(D1,[1,2]);
ok([...pi.keys()].every(k=>!pj.has(k)),"alternative pair separation");nchecks++;
const typ=new Map();
for(const p of G){const key=cls(p),d=dist([I,p]);if(typ.has(key)){ok(same(d,typ.get(key)),"class law");nchecks++;}else typ.set(key,d);}
ok(typ.size===5,"S4 partitions");nchecks++;
for(const [a,da] of typ)for(const [b,db] of typ)if(a<b){ok([...da.keys()].every(k=>!db.has(k)),"orbits separate");nchecks++;}
let q=0x9e3779b9;const step=()=>{q^=q<<13;q^=q>>>17;q^=q<<5;return q>>>0;};
const shuffle=()=>{const z=I.slice();for(let j=3;j>0;j--){const k=step()%(j+1);[z[j],z[k]]=[z[k],z[j]];}return z;};
let hits=0;
for(let i=0;i<256;i++){const bit=step()&1,Ts=bit?c1:c0,arr=tab(Ts,shuffle(),shuffle());const got=cls(mul(arr[1],inv(arr[2])))==="3,1"?1:0;ok(bit===got,"seed bit");hits++;nchecks++;}
return {run:546, result:"PASS", assertions:nchecks, mask_pairs_per_family:576, case0_support:D0.size, case1_support:D1.size, case0_weight:4, case1_weight:1, equal_marginals:["single table","base/alternative 1","base/alternative 2"], pair_alternatives_separated:true,s4_conjugacy_classes:typ.size,recovered_demo_bits:hits,scope:"Only transparent publicly composable shared-frame reversible tables; not WKEM or a PQ security proof."};
