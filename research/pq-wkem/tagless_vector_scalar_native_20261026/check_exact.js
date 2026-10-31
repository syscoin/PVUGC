/* Tagless vector SOURCE exact algebra checker. Not a native/PQ signature implementation. */
function checkPublished(){
 const mod=(x,q)=>(x%q+q)%q;
 let assertions=0;
 const ck=(b,m)=>{if(!b)throw Error(m);assertions++};
 const fc=(k,a,q)=>[mod(k+a[0],q),mod(a[1]-a[0],q),mod(a[2],q),mod(a[3]-a[1],q)];
 const residual=(u,v,q)=>[mod(1-u,q),mod(u*(1-v),q),mod(v,q)];
 for(let q of [2,3,5,17,257])for(let u=0;u<q;u++)for(let v=0;v<q;v++){
  const r=residual(u,v,q);
  ck(mod(r[0]+r[1]+u*r[2],q)===1,'formal identity');
  if(u<2&&v<2)ck(r.some(x=>x!==0),'false Boolean formula');
 }
 let laws=[];
 for(let q of [3,5]){
  let ref=null;
  for(let k=0;k<q;k++){
   const counts=new Map();
   for(let a=0;a<q;a++)for(let b=0;b<q;b++)for(let c=0;c<q;c++)for(let d=0;d<q;d++){
    const key=fc(k,[a,b,c,d],q).join(',');counts.set(key,(counts.get(key)||0)+1);
   }
   ck(counts.size===q**4,'full complete-array support');
   ck([...counts.values()].every(x=>x===1),'complete distribution uniform');
   const view=JSON.stringify([...counts.entries()].sort((a,b)=>a[0].localeCompare(b[0])));
   if(ref!==null)ck(ref===view,'conditional on any native key same full law'); else ref=view;
  }
  laws.push({field:q,all_coefficient_arrays:q**4,key_values:q});
 }
 let state=20261026;
 const rnd=()=>{state=(Math.imul(1664525,state)+1013904223)>>>0;return state};
 for(let it=0;it<1024;it++){
  const q=257;
  for(let coord=0;coord<2;coord++){
   const k=rnd()%q,delta=rnd()%q;
   const a=Array.from({length:4},()=>rnd()%q);
   const aa=[mod(a[0]-delta,q),mod(a[1]-delta,q),a[2],mod(a[3]-delta,q)];
   ck(fc(k,a,q).every((x,j)=>x===fc(mod(k+delta,q),aa,q)[j]),'whole-array bijective key shift');
   const u=rnd()%2,v=1;
   const s=rnd()%q,t=rnd()%q;
   const r1=mod((1-u)*(1-v),q),r2=mod(u*(1-v),q);
   ck(mod(k+s*r1+t*r2,q)===k,'two distinct true ORIGINAL witnesses return same exact key');
  }
 }
 return {component:'tagless_vector_scalar_covered_v01',assertions,fields:[2,3,5,17,257],laws,random_bijective_couplings:2048,honest_true_checks:2048,native_signature_security:'symbolic theorem only; not tested',generic_np_coverage:'not proved',hard_true:'public key recovery when 1 not in W'};
}
console.log(JSON.stringify(checkPublished(),null,2));
