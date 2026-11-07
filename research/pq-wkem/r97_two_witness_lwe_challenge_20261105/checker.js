function runR97(){
 let checks=0;let cases=[];
 const ok=(v,m)=>{checks++;if(!v)throw Error(`${checks} ${m}`);};
 for(const q of [7,11,13]){
   let total=0,both=0;
   for(let a=0;a<q;a++)for(let b=0;b<q;b++)for(let e0=-1;e0<=1;e0++)for(let e1=-1;e1<=1;e1++){
     let pk0=[(a+e0+q)%q,(b+e1+q)%q];
     let centered=v=>((v%q+q)%q);
     ok([pk0[0]-a,pk0[1]-b].every(v=>[q-1,0,1].includes(centered(v))),"first secret valid");
     if([pk0[0]-2*a,pk0[1]-2*b].every(v=>[q-1,0,1].includes(centered(v))))both++;
     total++;
   }
   ok(both*q*q===total*9,"exact (3/q)^2");
   cases.push({q,total,both,numerator:9,denominator:q*q});
 }
 const q=257,delta=128,A=[[1,0],[1,0],[0,1],[0,1]],B=[0,1,0,1];
 const centered=v=>{let x=(v%q+q)%q;return x>q/2?x-q:x};
 for(let t0 of [0,1,7,89])for(let t1 of [2,17,99,131]){
   const t=[t0,t1],b=B.map((v,i)=>(v+A[i][0]*t0+A[i][1]*t1)%q);
   for(let r0=0;r0<16;r0++){
     const r=[0,1,2,3].map(i=>(r0>>i)&1);
     const u=[0,1].map(j=>A.reduce((a,row,i)=>a+row[j]*r[i],0)%q);
     for(let bit of [0,1]){
       let v=(b.reduce((a,x,i)=>a+x*r[i],0)+delta*bit)%q;
       let vu=(v-t.reduce((a,x,i)=>a+x*u[i],0)+q*q)%q;
       let z0=Math.abs(centered(vu)),z1=Math.abs(centered(vu-delta));
       ok(Number(z1<z0)===bit,"public affine shift negative control");
     }
   }
 }
 return {run:"R97-TWO-WITNESS-LWE-CHALLENGE-20261105",status:"NO_POSITIVE_CONSTRUCTION_ADVANCE",assertions:checks,exact_census:cases,scope:"fixed distinct prescribed secrets independent of honest LWE challenge A; classical algebra check, no QPT claim",provenance:"executed V8 function source; no web"};
}
console.log(JSON.stringify(runR97(),null,2));
