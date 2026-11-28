'use strict';
// MINK-FWT exact deterministic algebra checker. NOT a quantum hardness test.
const q=65537,n=256,m=4800,t=2400,eta=3,g=21845;
let checks=0;
function ok(v,msg){checks++; if(!v)throw Error(msg)}
function log2choose(n,k){let v=0;for(let i=1;i<=k;i++)v+=Math.log2(n-k+i)-Math.log2(i);return v}
const support=log2choose(m,t), logeps=-1+((n+1)*Math.log2(q)-support)/2;
ok(t*eta < Math.min(g,q-2*g)/2,'three disjoint decoding intervals');
ok(logeps < -128,'fixed weight statistical bound');
ok(2*(n+1)*3 === 1542 && (n+1)*3===771,'exact byte reduction');
function decode(v,su,q,g,bound){let ret=[];for(let c=0;c<3;c++){let x=((v-su-g*c)%q+q)%q;if(Math.min(x,q-x)<=bound)ret.push(c)}return ret}
// Exhaust every fixed-weight r, every bounded error vector, and each color.
const a=[[3,7],[11,4],[1,9],[5,15],[14,2]], s=[8,13],Q=19,G=6;
let small=0;
for(let z=0;z<3**5;z++){
 let h=z,e=[];for(let i=0;i<5;i++){e.push(h%3-1);h=Math.floor(h/3)}
 let b=a.map((row,i)=>(row[0]*s[0]+row[1]*s[1]+e[i])%Q);
 for(let i=0;i<5;i++)for(let j=i+1;j<5;j++)for(let c=0;c<3;c++){
  let u=a[i].map((x,k)=>(x+a[j][k])%Q);
  let v=(b[i]+b[j]+G*c)%Q;
  let su=(u[0]*s[0]+u[1]*s[1])%Q;
  ok(decode(v,su,Q,G,2).join('')===String(c),'every toy ternary opening decrypts');
  small++;
 }
}
// Complete finite two-universal average-key calculation: q=2,n=1,m=5,t=2.
let collisions=0,totalTV=0;const rr=[];for(let i=0;i<5;i++)for(let j=i+1;j<5;j++)rr.push([i,j]);
for(let key=0;key<1024;key++){
 let hist=[0,0,0,0],out=[];
 for(const [i,j] of rr){let u=((key>>(2*i))^(key>>(2*j)))&1;
  let v=((key>>(2*i+1))^(key>>(2*j+1)))&1;
  let x=2*u+v;hist[x]++;out.push(x)}
 totalTV+=0.5*hist.reduce((z,x)=>z+Math.abs(x/10-0.25),0);
 for(let i=0;i<10;i++)for(let j=0;j<i;j++)if(out[i]===out[j])collisions++;
}
ok(collisions===1024*45/4,'exact pairwise universality');
ok(totalTV/1024 <= 0.5*Math.sqrt(4/10)+1e-12,'average TV leftover bound');
// Complete false K4 and decoder-disjointness checks.
let assignments=0;
for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++){
 let v=[a,b,c,d],bad=0;for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)if(v[i]===v[j])bad++;
 ok(bad>=1,'K4 admits no three-coloring');assignments++;
}
for(let z=0;z<q;z++)ok(decode(z,0,q,g,t*eta).length<=1,'global ternary center uniqueness');
const output={run:'MINK-FWT-20261102',checks,small_toy_cases:small,exhaustive_keys:1024,
 collision_pairs:collisions,average_toy_tv:totalTV/1024,full_q:q,full_n:n,full_m:m,
 fixed_weight:t,max_error:t*eta,ternary_gap:g,log2_support:support,
 log2_fixed_weight_epsilon:logeps,old_vertex_bytes:1542,new_vertex_bytes:771,
 quantum_hardness_estimated:false,generic_wkem_proved:false};
console.log(JSON.stringify(output,null,2));
