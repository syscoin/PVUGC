function runCheck(){
 const count={};const check=(c,g,why)=>{if(!c)throw Error(g+": "+why);count[g]=(count[g]??0)+1;};
 const par=x=>{let p=0;for(;x;x>>=1)p^=x&1;return p;};
 const dist=(mode,bit)=>Array.from({length:4},(_,y)=>mode===null?2:2+(bit? -1:1)*(par(mode&y)?-1:1));
 const ft=(p,a)=>p.reduce((t,w,y)=>t+w*(par(a&y)?-1:1),0);
 for(const mode of [null,1,3]){
  let a=dist(mode,0),b=dist(mode,1);
  check(a.reduce((u,v)=>u+v,0)===8&&b.reduce((u,v)=>u+v,0)===8,"normalization","column");
  for(let f=0;f<4;f++)check(ft(b,f)-ft(a,f)===(mode!==null&&f===mode?-8:0),"Fourier_support","entire law");
  if(mode===null)check(a.every((v,j)=>v===b[j]),"false_law","full equality");
 }
 for(let pk=0;pk<2;pk++)for(let s0=0;s0<2;s0++)for(let s1=0;s1<2;s1++)for(let y0=0;y0<4;y0++)for(let y1=0;y1<4;y1++){
  let joint=[];
  for(const K of [pk,pk+2]){
   let c0=((K>>1)&1)^s0,c1=((K>>1)&1)^s1;
   joint.push(dist(null,c0)[y0]*dist(null,c1)[y1]);
  }
  check(joint[0]===joint[1]&&joint[0]===4,"same_key_false_joint","pk,dithers,two full outputs");
 }
 for(const mode of [1,3])for(let K=0;K<4;K++)for(let S=0;S<2;S++){
  const bit=((K>>1)&1)^S;
  const d=dist(mode,bit);
  let mass=0;for(let y=0;y<4;y++)if(par(mode&y)===bit)mass+=d[y];
  check(mass===6,"witness_channel","same key bit with 3/4 correctness");
 }
 const A0=dist(1,0),A1=dist(1,1),B0=dist(3,0),B1=dist(3,1);
 let maxRatio=0,positive=0;
 for(let mask=0;mask<65536;mask++){
  let delta=0,da=0,db=0,q1=0,q2=0;
  for(let x=0;x<4;x++)for(let y=0;y<4;y++){
   const f=(mask>>(4*x+y))&1;
   delta+=f*(A1[x]*B1[y]-A0[x]*B0[y]);
   da+=f*(A1[x]-A0[x])*B1[y];
   db+=f*A0[x]*(B1[y]-B0[y]);
  }
  check(delta===da+db,"joint_telescope","adversarial full-view predicate");
  for(let y=0;y<4;y++){
   let t=0;for(let x=0;x<4;x++)t+=(par(x&1)?-1:1)*((mask>>(4*x+y))&1);
   q1+=B1[y]*t*t;
  }
  for(let x=0;x<4;x++){
   let t=0;for(let y=0;y<4;y++)t+=(par(y&3)?-1:1)*((mask>>(4*x+y))&1);
   q2+=A0[x]*t*t;
  }
  check(q1>=0&&q1<=32&&q2>=0&&q2<=32,"phase_reflection","QPT-compatible toy strategy");
  if(delta>0){
   positive++;
   check(delta*delta<=64*(q1+q2),"weighted_extractor_bound","no representation supplied");
   if(q1+q2)maxRatio=Math.max(maxRatio,delta*delta/(64*(q1+q2)));
  }
 }
 check(maxRatio===1,"bound_tight","two-source example saturates weighted inequality");
 return {status:"PASS",checks:Object.values(count).reduce((a,b)=>a+b,0),groups:count,strategies:65536,positiveGapStrategies:positive,maxSquaredRatio:maxRatio,
  scope:"exact small SOURCE quotients, native-pk-conditioned same-key joint laws, and coherent-phase toy; NOT QPT hardness or SYS/BTC proof"};
}
console.log(JSON.stringify(runCheck(),null,2));
