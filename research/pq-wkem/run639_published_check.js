'use strict';
let checks=0; const ok=(b)=>{checks++;if(!b)throw Error('assertion '+checks)};
const q=5, mod=x=>(x%q+q)%q;
const T=[[1,2],[2,1]], inv=[[3,4],[4,3]];
const mul=(X,Y)=>X.map(row=>Y[0].map((_,j)=>mod(row.reduce((s,x,k)=>s+x*Y[k][j],0))));
let distinct=new Set(), short=0;
const zs=[];
for(let a=-1;a<=1;a++)for(let b=-1;b<=1;b++)if(a||b)zs.push([a,b]);
for(let a=0;a<q;a++)for(let b=0;b<q;b++)for(let c=0;c<q;c++)for(let d=0;d<q;d++){
 const A=[[a,b],[c,d]],D=mul(inv,A);
 ok(JSON.stringify(mul(T,D))===JSON.stringify(A));
 distinct.add(D.flat().join(','));
 if(zs.some(z=>mod(D[0][0]*z[0]+D[0][1]*z[1])===1&&mod(D[1][0]*z[0]+D[1][1]*z[1])===0))short++;
}
ok(distinct.size===625);ok(zs.length===8);ok(short===180);ok(short*q*q<=zs.length*625);
const q2=17;ok((2*(-8)-1)%q2===0);ok((17-1)/2===8);
console.log(JSON.stringify({run:639,result:'PASS',checks,uniform_matrices:625,short_target_matrices:short,union_bound:'8/25',exact_probability:'36/125',tight_inverse_norm:8}));
