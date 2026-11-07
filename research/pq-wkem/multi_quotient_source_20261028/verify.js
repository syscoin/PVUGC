// Exact offline algebra: multi-quotient SOURCE, NOT a QPT/native signing test.
let N=0;const ok=(b,msg)=>{if(!b)throw Error(msg);N++};
const mod=(a,q)=>((a%q)+q)%q;
function counts(q){let c=Array(q).fill(0n);c[0]=1n;
 for(let j=1;j<=(q-1)/2;j++)c=c.map((_,i)=>c[mod(i-j,q)]+c[i]+c[mod(i+j,q)]);return c;}
for(const q of [5,17,257]){const c=counts(q),M=3n**BigInt((q-1)/2),zero=(M-BigInt(q-1))/BigInt(q),other=(M+1n)/BigInt(q);
 ok(c.reduce((a,b)=>a+b,0n)===M,'total');ok(c[0]===zero,'zero');
 for(let j=1;j<q;j++){ok(c[j]===other,'other');let t=0n;for(let i=0;i<q;i++)t+=c[i]>=c[mod(i-j,q)]?c[i]-c[mod(i-j,q)]:c[mod(i-j,q)]-c[i];ok(t===2n,'shift TV');}}
for(const q of [5,17]){const c=counts(q),M=3n**BigInt((q-1)/2);let t=0n;
 for(let i=0;i<q;i++)for(let j=0;j<q;j++){const a=c[i]*c[j],b=c[mod(i-1,q)]*c[j];t+=a>=b?a-b:b-a;}
 ok(t===2n*M,'two quotient TV');}
const A=[new Map(),new Map()];for(let u=0;u<5;u++)for(let v=0;v<5;v++)
for(let a=-1;a<=1;a++)for(let b=-1;b<=1;b++)for(let c=-1;c<=1;c++)for(let d=-1;d<=1;d++){
 const x=[mod(-2*u+a,5),mod(u+b,5),mod(-2*v+c,5),mod(v+d,5)];
 const y=[mod(x[0]+1,5),x[1],x[2],x[3]];
 for(let k=0;k<2;k++){const s=(k?y:x).join(',');A[k].set(s,(A[k].get(s)||0)+1);}
 ok(mod(x[0]+2*x[1],5)===mod(a+2*b,5),'first source');
 ok(mod(x[2]+2*x[3],5)===mod(c+2*d,5),'second source');
}
let diff=0;for(const k of new Set([...A[0].keys(),...A[1].keys()]))diff+=Math.abs((A[0].get(k)||0)-(A[1].get(k)||0));
ok(diff===2*5*5*9,'full p TV=1/9');
for(const q of [5,17,257]){const h=(q-1)/2;
 for(let j=1;j<2*h;j++){let w=Array(2*h).fill(0);w[0]=w[j]=1;let good=true;
  for(const off of [0,h])for(let k=1;k<h;k++)if(mod(w[off+k]-(k+1)*w[off],q)!==0)good=false;
  ok(!good,'false original');}}
let state=20261028;function rnd(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0}
function bytes(){return Uint8Array.from({length:32},()=>rnd()%256)}
const xx=(...v)=>Uint8Array.from({length:32},(_,i)=>v.reduce((r,x)=>r^x[i],0));
const asInt=b=>b.reduce((a,x)=>(a<<8n)+BigInt(x),0n);
for(let run=0;run<12;run++){const K=bytes(),U=bytes(),Z=bytes(),D=xx(U,Z),V=xx(K,U);let z=asInt(Z),ds=[];
 for(let j=0;j<46;j++){ds.push(Number(z%51n));z/=51n}ok(z===0n,'pad capacity');
 for(const digit of ds){const u=rnd()%257,E=[rnd()%3-1,rnd()%3-1,rnd()%3-1];
  const p=[mod(u+E[0]+5*digit,257),mod(-u+E[1],257),mod(-u+E[2],257)];
  for(const phase of [mod(p[0]+p[1],257),mod(p[0]+p[2],257)]){
   let dec=[];for(let k=0;k<51;k++){let d=mod(phase-5*k,257);if(Math.min(d,257-d)<=2)dec.push(k)}
   ok(dec.length===1&&dec[0]===digit,'both true witnesses');}}
 ok(asInt(xx(D,V,Z))===asInt(K),'same whole seed');}
console.log(JSON.stringify({result:'PASS',assertions:N,q5_full_vector_tv:'1/9',q257_two_quotient_tv:'1/3^128',full_seed_trials:12,hard_true_reduction:false}));
