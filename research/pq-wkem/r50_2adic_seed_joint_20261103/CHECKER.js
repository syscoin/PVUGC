'use strict';
function r50(){
 const q=8,m=3,h=2;let matrices=0,noninjective=0,checks=0;
 for(let a=0;a<q;a++)for(let b=0;b<q;b++)for(let c=0;c<q;c++){
  matrices++;const found=new Set();let collision=false;
  for(let s=0;s<q;s++)for(let e0=0;e0<h;e0++)for(let e1=0;e1<h;e1++)for(let e2=0;e2<h;e2++){
    const y=[(a*s+e0)%q,(b*s+e1)%q,(c*s+e2)%q].join(',');
    if(found.has(y))collision=true;found.add(y);checks++;
  }
  if(collision)noninjective++;
 }
 if(matrices!==512||noninjective!==116||checks!==32768)throw Error('matrix count mismatch');
 const terms=[];for(let r=0;r<3;r++){
  const nr=2**(3-r)-2**(2-r),d=2*Math.floor(1/2**r)+1;
  terms.push(nr*d**m*128/(2**(3-r))**m);
 }
 if(JSON.stringify(terms)!==JSON.stringify([27,4,16]))throw Error('2-adic bound');
 if(noninjective*128>matrices*terms.reduce((x,y)=>x+y,0))throw Error('union bound');
 return {run:'R50-2ADIC-SEED-JOINT-20261103',matrices,noninjective,
   collision_rate:'29/128',union_bound:'47/128',bound_terms_over_128:terms,
   sampled_seed_images:checks,quantum_hardness:'NOT TESTED',hard_TRUE_extraction:'NOT PROVED'};
}
const a=r50(),b=r50();if(JSON.stringify(a)!==JSON.stringify(b))throw Error('repeat mismatch');
console.log(JSON.stringify({result:a,repeat_identical:true},null,2));
