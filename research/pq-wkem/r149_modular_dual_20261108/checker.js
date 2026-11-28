'use strict';
const qcases = [
 {name:'original-2cnf',M:[[0,-1,0,1,0,0],[0,0,-1,0,0,1],[1,-1,-1,0,1,0]],v:[1,0,1,0,0,1],a:[4,1,1,1,-2,1],d:4,q:65521,delta:1024},
 {name:'integer-optimum-synthetic',M:[[-6,1,5,0,0],[0,0,-1,1,0],[0,0,-1,0,1]],v:[1,1,1,1,1],a:[5,0,6,6,6],d:5,q:65521,delta:1024},
 {name:'denominator-resonance-synthetic',M:[[-5,1,4,0,0],[0,0,-1,1,0],[0,0,-1,0,1]],v:[1,1,1,1,1],a:[4,0,5,5,5],d:4,q:4096,delta:1024}
];
let checks=0;
const ck=x=>{checks++;if(!x)throw Error('assertion '+checks)};
const dot=(a,b)=>a.reduce((t,x,i)=>t+x*b[i],0);
const mod=(x,q)=>(x%q+q)%q;
const dist=(x,q)=>Math.min(mod(x,q),mod(-x,q));
const dec=(z,q,delta)=>dist(z,q)<dist(z-delta,q)?0:1;
let rng=149;
const rnd=m=>{rng=(Math.imul(rng,1664525)+1013904223)>>>0;return rng%m;};
const output=[];
for(const t of qcases){
 const N=t.v.length,A=[...t.M,[1,...Array(N-1).fill(0)]],b=[...Array(t.M.length).fill(0),1];
 for(let j=0;j<A.length;j++){ck(dot(A[j],t.v)===b[j]);ck(dot(A[j],t.a)===t.d*b[j]);}
 let E=t.d+t.a.reduce((a,v)=>a+Math.abs(v),0),H=1+t.v.reduce((a,v)=>a+Math.abs(v),0);
 ck(E/t.d<=H);
 let D=dist(t.d*t.delta,t.q),sep=D>2*E;
 let samples=0,collisions=0;
 for(let r=0;r<10;r++){
   const s=A.map(()=>rnd(t.q));
   for(let tape=0;tape<3**(N+1);tape++){
     let z=tape,noise=[];
     for(let j=0;j<N+1;j++){noise.push(z%3-1);z=Math.floor(z/3);}
     const e=noise.slice(0,N),eta=noise[N];
     const c=e.map((n,i)=>mod(dot(A.map(row=>row[i]),s)+n,t.q));
     const p=mod(s.at(-1)+eta,t.q);
     for(let K=0;K<2;K++){
       let P=mod(p+t.delta*K,t.q);
       const honest=mod(P-dot(t.v,c),t.q),leak=mod(t.d*P-dot(t.a,c),t.q);
       ck(dist(honest-t.delta*K,t.q)<=H);ck(dec(honest,t.q,t.delta)===K);
       ck(leak===mod(t.d*t.delta*K+t.d*eta-dot(t.a,e),t.q));
       if(sep){ck(dec(leak,t.q,t.d*t.delta)===K);ck(dist(leak-t.d*t.delta*K,t.q)<=E);}
       else if(K===1&&D===0){ck(leak===mod(t.d*p-dot(t.a,c),t.q));collisions++;}
       samples++;
     }
   }
 }
 output.push({case:t.name,N,denominator:t.d,honestBound:H,publicBound:E,circularDistance:D,publicGuaranteed:sep,samples,collisions});
}
let mins=Array.from({length:101},(_,j)=>j-50).map(u=>[u,1+Math.abs(6-5*u)+3*Math.abs(u)]).sort((a,b)=>a[1]-b[1]);
ck(mins[0][0]===1&&mins[0][1]===5);
console.log(JSON.stringify({checks,output},null,2));
