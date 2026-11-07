// Run 425: exact S2/S3 boundary-label transcript law. No security proof for WE.
const perms=a=>a.length<2?[a]:a.flatMap((v,i)=>perms(a.filter((_,j)=>j!==i)).map(t=>[v,...t]));
const mul=(p,q)=>q.map(v=>p[v]);
const inv=p=>{let r=Array(p.length);p.forEach((v,i)=>r[v]=i);return r};
let assertions=0;
function ck(x){assertions++;if(!x)throw Error('Run425 assertion '+assertions)}
const cases=[];
for(const d of [2,3]){
 const P=perms([...Array(d).keys()]),laws=[null,null],counts=[0,0];
 for(const F0 of P)for(const F1 of P){
  const e=+(mul(F1,F0)[0]===0),dist=new Map(),A=new Map(),B=new Map();counts[e]++;
  for(const M0 of P)for(const M1 of P)for(const M2 of P){
   const G0=mul(mul(M1,F0),inv(M0)),G1=mul(mul(M2,F1),inv(M1));
   const L=M0[0],T=M2[0];ck(+(G1[G0[L]]===T)===e);
   for(const [map,key] of [[dist,[G0,G1,L,T]],[A,[G0,L]],[B,[G1,T]]]){
    const k=JSON.stringify(key);map.set(k,(map.get(k)||0)+1);
   }
  }
  const n=P.length;
  ck(A.size===n*d&&B.size===n*d);
  ck([...A.values()].every(c=>c===n*n/d));
  ck([...B.values()].every(c=>c===n*n/d));
  ck(dist.size===n*n*d*(e?1:d-1));
  ck([...dist.values()].every(c=>c===n*n*n/dist.size));
  const serialized=JSON.stringify([...dist].sort());
  if(laws[e]===null)laws[e]=serialized;
  ck(laws[e]===serialized);
 }
 ck(laws[0]!==laws[1]);
 ck(counts[1]===P.length*P.length/d);
 cases.push({d,source_pairs:P.length**2,mask_triples_per_pair:P.length**3,false_assignments:counts[0],true_assignments:counts[1],isolated_capsule_support:P.length*d,joint_support_false:P.length**2*d*(d-1),joint_support_true:P.length**2*d});
}
console.log(JSON.stringify({run:425,assertions,cases,qpt:'classical information-theoretic falsifier; not a PQ WE proof',complete_wkem:false},null,2));
