// Run 427 compact independent checker. Node 20+; no external dependencies.
// Only finite permutation enumeration, not cryptographic security validation.
'use strict';
let assertions = 0;
const test = (v,label) => { assertions++; if (!v) throw Error(label); };
const permutations = a => a.length===0 ? [[]] : a.flatMap((v,i)=>permutations([...a.slice(0,i),...a.slice(i+1)]).map(p=>[v,...p]));
const compose = (a,b) => b.map(j=>a[j]);
const inverse = p=>{const a=[];p.forEach((j,i)=>{a[j]=i});return a;};
const lift = f => {const a=[];f.forEach((v,x)=>{for(let z=0;z<2;z++)a.push(2*x+(z+v)%2)});return a;};
const tuple = s=>JSON.stringify(s);
const inc=(m,k)=>m.set(k,(m.get(k)||0)+1);
function sample(f,U,V){
 const g=compose(compose(V,lift(f)),inverse(U));
 const a=f.map((_,i)=>U[2*i]).sort((x,y)=>x-y);
 const b=[0,1].map(y=>f.map((_,i)=>V[2*i+y]).sort((x,y)=>x-y));
 return [g,a,b];
}
function spectrum(z){const [g,a,b]=z;const im=new Set(a.map(v=>g[v]));return b.map(B=>B.filter(x=>im.has(x)).length);}
function mapsEqual(a,b){ if(a.size!==b.size)return false;for(const [k,v] of a)if(b.get(k)!==v)return false;return true;}
const perms=permutations([0,1,2,3]);
const maps=[[0,0],[0,1],[1,0],[1,1]];
const full=[], first=[], second=[];
for(const f of maps){
 let c=new Map(), a=new Map(), b=new Map();
 for(const U of perms)for(const V of perms){
  const record=sample(f,U,V);
  test(tuple(spectrum(record))===tuple([f.filter(x=>x===0).length,f.filter(x=>x===1).length]),'exact histogram');
  inc(c,tuple(record));inc(a,tuple(record.slice(0,2)));inc(b,tuple([record[0],record[2]]));
 }
 test([...c.values()].reduce((a,b)=>a+b,0)===576,'mass');
 test(new Set(c.values()).size===1,'uniform conditional');
 full.push(c);first.push(a);second.push(b);
}
let pairChecks=0;
for(let i=0;i<maps.length;i++)for(let j=i+1;j<maps.length;j++){
 const eq=maps[i].filter(x=>x===1).length===maps[j].filter(x=>x===1).length;
 test(mapsEqual(full[i],full[j])===eq,'joint same precisely for same histogram');
 test(mapsEqual(first[i],first[j]),'first boundary marginal');
 test(mapsEqual(second[i],second[j]),'second boundary marginal');
 if(!eq)test(![...full[i].keys()].some(k=>full[j].has(k)),'disjoint supports');
 pairChecks++;
}
const summary={run:427,independent_checker:'JavaScript',assertions,
  exhaustive_maps:maps.length,mask_pairs_per_map:576,pairwise_laws:pairChecks,
  support_sizes:full.map(z=>z.size),
  conclusion:'input clean set and output partition jointly leak histogram; either interface alone uniform',
  complete_practical_pq_wkem:false};
process.stdout.write(JSON.stringify(summary,null,2)+'\n');
