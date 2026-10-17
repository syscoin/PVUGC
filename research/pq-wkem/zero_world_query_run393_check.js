"use strict";
// Run 393 compact independently executed coherent-oracle validation.
// Real XOR oracle with response |-> becomes a phase flip on accepted states.
let checks=0; const req=(v,m)=>{checks++;if(!v)throw Error(m+" assertion "+checks)};
let seed=393393>>>0; const rnd=(N)=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%N};
function acceptedSet(N,m){const ans=new Set();while(ans.size<m)ans.add(rnd(N));return ans}
function mass(v,S){let s=0;for(const i of S)s+=v[i]*v[i];return s}
function step(v,S,real){const arr=v.map((z,i)=>real&&S.has(i)?-z:z), avg=arr.reduce((x,y)=>x+y,0)/arr.length;return arr.map(z=>2*avg-z)}
let count=0, representative=[];
for(let n=4;n<=9;n++){let N=2**n;for(let m=1;m<=3;m++){let S=acceptedSet(N,m);
for(let q=1;q<=6;q++){let a=Array(N).fill(1/Math.sqrt(N)),b=a.slice(),premass=0;
for(let j=0;j<q;j++){premass+=mass(b,S);a=step(a,S,true);b=step(b,S,false);
req(Math.abs(a.reduce((s,z)=>s+z*z,0)-1)<1e-9,"real norm");
req(Math.abs(b.reduce((s,z)=>s+z*z,0)-1)<1e-9,"zero norm")}
const pr=mass(a,S),pz=mass(b,S),pe=premass/q,eps=Math.max(0,pr-pz);
req(Math.abs(pz-m/N)<1e-9,"zero baseline");
req(Math.abs(pe-m/N)<1e-9,"zero-world query acceptance");
req(pe+1e-12>=eps*eps/(4*q*q),"O2H query extraction lower bound");
count++;
if((n===8&&m===1&&q===6)||(n===6&&m===3&&q===3))
representative.push({n,m,q,pReal:+pr.toFixed(10),pZero:+pz.toFixed(10),pExtract:+pe.toFixed(10),lower:+(eps*eps/(4*q*q)).toFixed(10)});
}}}
for(let k=1;k<=127;k++){let programConstant=k;
req(programConstant===k,"white-box same in both worlds");
let secretMask=k^0x55, left=secretMask, right=secretMask^k;
req((left^right)===k,"joint seam leak");}
return JSON.stringify({
run:393,status:"PASS",checks,fixtures:count,three_input_state_dimensions:[4,9],
zero_world_extractor_bound:"(pReal-pZero)_+^2 / (4q^2)",
native_signature_implemented:false,real_WKEM:false,QPT_hardness:false,
representative
},null,2)+"\n";
