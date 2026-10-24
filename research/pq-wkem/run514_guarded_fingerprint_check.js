// Run 514 compact exact fingerprint checker, no cryptographic security assertion.
let count={frames:0,maps:0,involution:0,fixed:0,commutation:0,valid_bits:0,false_identity:0,cycle_law:0};
function ok(p,k){if(!p)throw Error("assertion "+k);count[k]++;}
function bitcount(a){let t=0;while(a){t+=a&1;a>>>=1;}return t;}
function check(h,n,delta,f,p){
 const N=1<<(h+n+1),inv=new Array(N),m=bitcount(f), gates=[];
 for(let a=0;a<N;a++)inv[p[a]]=a;
 for(let i=0;i<h;i++){
  let g=new Array(N);
  for(let y=0;y<N;y++){let v=inv[y],z=(v>>1)&((1<<n)-1),u=v>>(n+1),b=(((u>>i)^(delta>>i))&1)&((f>>z)&1);g[y]=p[v^b];}
  gates.push(g);count.maps++;
  ok(g.every((v,y)=>g[v]===y),"involution");
  ok(g.filter((v,y)=>v===y).length===N-(1<<h)*m,"fixed");
  if(!m)ok(g.every((v,y)=>v===y),"false_identity");
 }
 for(let i=0;i<h;i++)for(let j=i+1;j<h;j++)
  ok(gates[i].every((v,y)=>gates[i][gates[j][y]]===gates[j][gates[i][y]]),"commutation");
 for(let K=0;K<(1<<h);K++)for(let z=0;z<(1<<n);z++)if((f>>z)&1){
  let y=p[((K^delta)<<(n+1))|(z<<1)];
  for(let i=0;i<h;i++)ok((gates[i][y]!==y)===!!((K>>i)&1),"valid_bits");
 }
 count.frames++;
}
const p=[0,1,2,3,4,5,6,7];
function permute(d){if(d===8){for(let delta=0;delta<2;delta++)for(let f=0;f<4;f++)check(1,1,delta,f,p);return;}
 for(let j=d;j<8;j++){[p[d],p[j]]=[p[j],p[d]];permute(d+1);[p[d],p[j]]=[p[j],p[d]];}}
permute(0);
let rng=514;function rand(){rng=(Math.imul(rng,1664525)+1013904223)>>>0;return rng;}
for(let t=0;t<24;t++){let q=Array.from({length:16},(_,i)=>i);for(let i=15;i>0;i--){let j=rand()%(i+1);[q[i],q[j]]=[q[j],q[i]];}
 for(let delta=0;delta<4;delta++)for(let f=0;f<4;f++)check(2,1,delta,f,q);
}
for(let N=3;N<=6;N++){
 let a=Array.from({length:N},(_,i)=>i),c=0,c1=0,c2=0;
 function walk(d){if(d===N){c++;if(a[0]===0)c1++;if(a[a[0]]===0)c2++;return;}for(let j=d;j<N;j++){[a[d],a[j]]=[a[j],a[d]];walk(d+1);[a[d],a[j]]=[a[j],a[d]];}}
 walk(0);ok(c1*N===c,"cycle_law");ok(c2*N===2*c,"cycle_law");
}
return {run:514,status:"PASS",seed:514,counts:count,scope:"finite invariant checks only; not a practical or QPT security proof"};
