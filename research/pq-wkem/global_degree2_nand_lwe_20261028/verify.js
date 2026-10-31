// Offline exact degree-two NAND source check; algebra only, NOT QPT security.
const q=65537;let checks=0;const mod=x=>((x%q)+q)%q;
function ok(x,msg){if(!x)throw Error(msg);checks++}
function compiler(gates,n){
 const v=n+gates.length,m=1+2*v+4*gates.length;
 const u=(i,b)=>1+2*i+b,t=(j,k)=>1+2*v+4*j+k,C=[];
 function row(xs){const d=new Map();for(const [i,a] of xs)d.set(i,mod((d.get(i)||0)+a));C.push(d)}
 for(let i=0;i<v;i++)row([[u(i,0),1],[u(i,1),1],[0,-1]]);
 gates.forEach(([a,b],j)=>{
  row([...Array.from({length:4},(_,k)=>[t(j,k),1]),[0,-1]]);
  row([[t(j,2),1],[t(j,3),1],[u(a,1),-1]]);
  row([[t(j,1),1],[t(j,3),1],[u(b,1),-1]]);
  row([[t(j,0),1],[t(j,1),1],[t(j,2),1],[u(n+j,1),-1]]);
 });row([[u(v-1,1),1],[0,-1]]);
 const mon=[];for(let i=0;i<m;i++)for(let j=i;j<m;j++)mon.push([i,j]);
 const ix=new Map(mon.map(([a,b],i)=>[a+','+b,i]));
 const col=(i,j)=>ix.get(Math.min(i,j)+','+Math.max(i,j));
 const F=[];function add(d){F.push(new Map([...d].filter(([i,a])=>mod(a)).map(([i,a])=>[i,mod(a)])))}
 C.forEach(r=>{for(let i=0;i<m;i++){
  const d=new Map();for(const [j,a] of r){const k=col(i,j);d.set(k,(d.get(k)||0)+a)}add(d)
 }});
 for(let i=1;i<m;i++)add(new Map([[col(i,i),1],[col(0,i),-1]]));
 return {C,F,mon,m,v,h:1+v+gates.length,u,t,gates,n,col};
}
function moment(S,z){return S.mon.map(([i,j])=>mod(z[i]*z[j]))}
function mul(F,x){return F.map(r=>mod([...r].reduce((s,[i,a])=>s+a*x[i],0)))}
function combine(F,y,D){const p=Array(D).fill(0);
 F.forEach((r,k)=>{for(const [i,a] of r)p[i]=mod(p[i]+a*y[k])});return p}
function inverse(a){let b=q,x=1,y=0;while(b){let t=Math.floor(a/b);[a,b]=[b,a-t*b];[x,y]=[y,x-t*y]}return mod(x)}
function subtract(d,trace,pr,pt,a){
 for(const [k,v] of pr){const b=mod((d.get(k)||0)-a*v);if(b)d.set(k,b);else d.delete(k)}
 for(const [k,v] of pt){const b=mod((trace.get(k)||0)-a*v);if(b)trace.set(k,b);else trace.delete(k)}
}
function certificate(F,target){const piv=new Map();
 F.forEach((row,i)=>{const d=new Map(row),trace=new Map([[i,1]]);
  while(d.size){const j=Math.min(...d.keys());if(!piv.has(j)){
   const inv=inverse(d.get(j));for(const [k,v] of d)d.set(k,mod(v*inv));
   for(const [k,v] of trace)trace.set(k,mod(v*inv));piv.set(j,[d,trace]);break
  }const [r,t]=piv.get(j);subtract(d,trace,r,t,d.get(j))}
 });const d=new Map([[target,1]]),res=new Map();
 while(d.size){const j=Math.min(...d.keys());if(!piv.has(j))return {rank:piv.size,coef:null};
  const [r,t]=piv.get(j),a=d.get(j);
  for(const [k,v] of r){const b=mod((d.get(k)||0)-a*v);if(b)d.set(k,b);else d.delete(k)}
  for(const [k,v] of t)res.set(k,mod((res.get(k)||0)+a*v));
 }return {rank:piv.size,coef:res}
}
function lift(S,bits){const w=bits.slice();for(const [a,b] of S.gates)w.push(1-w[a]*w[b]);
 if(!w.at(-1))return null;const z=Array(S.m).fill(0);z[0]=1;
 w.forEach((b,i)=>z[S.u(i,b)]=1);
 S.gates.forEach(([a,b],j)=>z[S.t(j,2*w[a]+w[b])]=1);return z}
let state=20261028;function rand(){state^=state<<13;state^=state>>>17;state^=state<<5;return(state>>>0)}
const F=compiler([[0,0],[0,1],[2,2]],1),D=F.mon.length;
const proof=certificate(F.F,F.col(0,0));ok(proof.coef!==null,'false certificate');
ok(D===231&&F.F.length===377&&proof.rank===230&&proof.coef.size===112,'false dimensions');
const check=Array(D).fill(0);for(const [j,a] of proof.coef)for(const [i,v] of F.F[j])check[i]=mod(check[i]+a*v);
ok(check.every((x,i)=>x===(i===F.col(0,0)?1:0)),'full certificate equality');
ok(lift(F,[0])===null&&lift(F,[1])===null,'false ORIGINAL');
const T=compiler([[0,1]],2),valid=[[0,0],[0,1],[1,0]];
const openings=valid.map(bits=>{const z=lift(T,bits);ok(!!z,'valid original');
 const f=moment(T,z);ok(mul(T.F,f).every(x=>x===0),'global quadratic kernel');return f});
let B=T.h*(T.h+1)/2,g=2*B+1,b=Math.floor(q/g),ell=0,capacity=1n;
while(capacity<(1n<<256n)){capacity*=BigInt(b);ell++}
ok(T.F.length===98&&T.mon.length===66&&g===31&&b===2114&&ell===24,'true sizes');
let Z=0n;for(let i=0;i<8;i++)Z=(Z<<32n)|BigInt(rand());
let a=[];for(let i=0;i<ell;i++){a.push(Number(Z%BigInt(b)));Z/=BigInt(b)}ok(Z===0n,'pad capacity');
const rec=openings.map(()=>[]);
for(const digit of a){const y=Array.from({length:T.F.length},()=>rand()%q);
 const e=Array.from({length:T.mon.length},()=>rand()%3-1),p=combine(T.F,y,T.mon.length);
 for(let j=0;j<p.length;j++)p[j]=mod(p[j]+e[j]+(j===T.col(0,0)?g*digit:0));
 for(let k=0;k<openings.length;k++){
  const phase=mod(openings[k].reduce((s,v,j)=>s+v*p[j],0));
  const d=Math.floor(phase/g),possible=[0,b-1,d-1,d,d+1].filter(x=>x>=0&&x<b);
  const good=[...new Set(possible)].filter(x=>Math.min(mod(phase-g*x),mod(g*x-phase))<=B);
  ok(good.length===1&&good[0]===digit,'same digit recovery');rec[k].push(good[0]);
 }}
const numbers=rec.map(xs=>xs.reduceRight((acc,x)=>acc*BigInt(b)+BigInt(x),0n));
ok(numbers.every(x=>x===numbers[0]),'same 256-bit pad for 3 original witnesses');
console.log(JSON.stringify({status:'PASS',assertions:checks,q,falseRows:F.F.length,falseMonomials:D,falseRank:proof.rank,certificateTerms:proof.coef.size,trueRows:T.F.length,trueMonomials:T.mon.length,validWitnesses:3,radix:b,columns:ell,sameCapability:true,hardTrueSecurityProved:false}));
