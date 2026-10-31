function verify(){
 let n=0;function check(a,m){if(!a)throw Error(m);n++}
 const mod=(x,q)=>((x%q)+q)%q;
 function law(a){const q=11,g=5,w=[1,1,0,0],o=new Map();
  for(let u0=0;u0<q;u0++)for(let u1=0;u1<q;u1++)for(let u2=0;u2<q;u2++)
  for(let e0=-1;e0<=1;e0++)for(let e1=-1;e1<=1;e1++)for(let e2=-1;e2<=1;e2++)for(let e3=-1;e3<=1;e3++){
   let p=[mod(e0+5*a-u0,q),mod(e1+u0,q),mod(e2+u1,q),mod(e3+u2,q)];
   check(mod(p[0]+p[1],q)===mod(e0+e1+5*a,q),"full mask cancellation");
   const k=p.join(",");o.set(k,(o.get(k)||0)+1);
  }
  return o;
 }
 const P0=law(0),Pa=law(1);
 function smooth(A,i){const o=new Map();for(const [k,c] of A){const v=k.split(",").map(Number);for(let t=0;t<11;t++){v[i]=mod(v[i]+1,11);const z=v.join(",");o.set(z,(o.get(z)||0)+c)}}return o;}
 function equal(A,B){if(A.size!==B.size)return false;for(const [k,c]of A)if(B.get(k)!==c)return false;return true;}
 function scaled(A,m){return new Map([...A].map(([k,c])=>[k,c*m]));}
 check(equal(smooth(P0,1),smooth(Pa,1)),"complete hit vectors");
 check(equal(smooth(P0,2),scaled(P0,11)),"miss full P0");
 check(equal(smooth(Pa,2),scaled(Pa,11)),"miss full Pa");
 check(!equal(smooth(P0,2),smooth(Pa,2)),"digit distinction on miss");
 function quotient(A){const o=Array(11).fill(0);for(const [k,c]of A){const p=k.split(",").map(Number);o[(p[0]+p[1])%11]+=c;}return o;}
 const base0=quotient(P0),baseA=quotient(Pa);
 for(let mask=0;mask<16;mask++){
  let a=base0.slice(),b=baseA.slice();let hit=!!(mask&3);
  for(let i=0;i<4;i++)if(mask&(1<<i)){
   let c=Array(11).fill(0),d=Array(11).fill(0);
   for(let t=0;t<11;t++)for(let z=0;z<11;z++){c[t]+=a[mod(t-(i<2?z:0),11)];d[t]+=b[mod(t-(i<2?z:0),11)]}
   a=c;b=d;
  }
  check(a.every((x,j)=>(x===b[j]))===hit,"all subgroup label laws");
 }
 let seed=20261028>>>0;function rnd(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;}
 const ri=(m)=>Math.floor(rnd()*m),M=256,q=257,h=8,g=17,W=[0,7,19,34,68,111,173,245];
 function sample(a){let p=Array(M);for(let i=0;i<M;i++)p[i]=ri(3)-1;p[0]=mod(p[0]+g*a,q);
  for(let i=1;i<M;i++){let u=ri(q);p[i]=mod(p[i]+u,q);if(W.includes(i))p[0]=mod(p[0]-u,q)}
  return p;
 }
 function win(p){let z=0;for(const i of W)z+=p[i];let d=mod(z-g,q);d=Math.min(d,q-d);
  return rnd()<(d<=h?0.8:0.2)?1:0;
 }
 function hit(S){let total=0;for(let k=0;k<380;k++){
  const v=S.map(i=>ri(q)),a=sample(1),b=sample(0);
  S.forEach((i,j)=>{a[i]=mod(a[i]+v[j],q);b[i]=mod(b[i]+v[j],q)});
  total+=win(a)-win(b);
 }return total/380<.2625;}
 let queries=0,R=Array(M).fill(0);R[0]=1;
 function dfs(lo,hi){if(lo>=hi)return;queries++;const S=[];for(let i=lo;i<hi;i++)S.push(i);
  if(!hit(S))return;
  if(hi-lo===1){R[lo]=1;return}
  let m=(lo+hi)>>1;dfs(lo,m);dfs(m,hi)
 }
 dfs(1,M);
 check(W.length===h,"weight");
 check(R.every((v,i)=>v===(W.includes(i)?1:0)),"actual original recovered");
 check(queries<M-1,"fewer groups");
 for(let t=0;t<12;t++){let a=ri(51),u=ri(257),e=Array.from({length:4},()=>ri(3)-1);
  const p=[mod(u+e[0]+5*a,257),mod(-u+e[1],257),mod(-u+e[2],257),mod(e[3],257)];
  for(const w of [[1,1,0,0],[1,0,1,0]]){
   let phase=mod(w.reduce((s,b,i)=>s+b*p[i],0),257),cand=[];
   for(let d=0;d<51;d++){let z=mod(phase-5*d,257);if(Math.min(z,257-z)<=2)cand.push(d)}
   check(cand.length===1&&cand[0]===a,"same digit");
  }
 }
 return {status:"PASS",assertions:n,full_q11_states:P0.size,all_group_subsets:16,group_queries:queries,coordinate_queries:255,actual_witness_indices:W,dual_witness_digit_trials:12,scope:"bounded classical checks; no independent QPT hardness"};
}
console.log(JSON.stringify(verify()));
