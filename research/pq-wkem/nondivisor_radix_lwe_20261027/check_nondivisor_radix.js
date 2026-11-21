// Self-contained Node >=18, standard library only. Executed independently as pure JS.
function checkNondivisorRadix(){
  let checks=0;const ok=(a,s)=>{checks++;if(!a)throw Error("check "+checks+" failed: "+s)};
  const mod=(x,q)=>((x%q)+q)%q,dot=(a,b,q)=>mod(a.reduce((s,x,i)=>s+x*b[i],0),q);
  const digits=(z,m,e)=>{let v=BigInt(z),out=[];for(let j=0;j<e;j++){out.push(Number(v%BigInt(m)));v/=BigInt(m)}ok(v===0n,"digit capacity");return out};
  const undigits=(ts,m)=>ts.reduceRight((z,t)=>z*BigInt(m)+BigInt(t),0n);
  const nearest=(v,q,g,m)=>{const clamp=t=>Math.max(0,Math.min(m-1,t)),lo=Math.floor(v/g);let win=-1,best=q+1,tie=false;for(const t of new Set([clamp(lo),clamp(lo+1),0,m-1])){const diff=mod(v-t*g,q),dist=Math.min(diff,q-diff);if(dist<best){best=dist;win=t;tie=false}else if(dist===best)tie=true}ok(!tie,"nonambiguous decoder");return win};
  const q=32,h=2,n=4,g=6,c=3,m=Math.floor(q/g),ell=2,k=4,B=[1,31,2,30];let W=[];
  ok(q%g!==0&&c*n<q&&m**ell>=2**k,"toy valid");
  for(let mask=0;mask<1<<n;mask++){const w=Array.from({length:n},(_,i)=>(mask>>i)&1),wt=w.reduce((a,b)=>a+b,0),is=wt===h&&dot(B,w,q)===0,A=[Array(n).fill(c),B.map(x=>mod(x+3*c,q))],aw=A.map(row=>dot(row,w,q));ok((aw[0]===g&&aw[1]===mod(3*g,q))===is,"source predicate");if(is)W.push(w)}
  ok(W.length===2,"two source witnesses");
  for(let t=0;t<m;t++)for(let e=-2;e<=2;e++)ok(nearest(mod(g*t+e,q),q,g,m)===t,"cyclic decoder");
  for(let K=0;K<16;K++){const tally=new Map();for(let U=0;U<16;U++)for(let Z=0;Z<16;Z++){const key=`${U^Z},${K^U}`;tally.set(key,(tally.get(key)||0)+1);ok(undigits(digits(Z,m,ell),m)===BigInt(Z),"inverse digits")}ok(tally.size===256&&[...tally.values()].every(x=>x===1),"full fixed-native-key null law")}
  for(let Z=0;Z<16;Z++){const ts=digits(Z,m,ell);for(let u=0;u<q;u++)for(let e0=-1;e0<=1;e0++)for(let e1=-1;e1<=1;e1++)for(let e2=-1;e2<=1;e2++)for(let e3=-1;e3<=1;e3++){const e=[e0,e1,e2,e3],recovered=[];for(let j=0;j<ell;j++){const p=B.map((b,i)=>mod(c*ts[j]+b*u+e[i],q)),lwe=B.map((b,i)=>mod(b*u+e[i],q));for(let i=0;i<n;i++)ok(p[i]===mod(c*ts[j]+lwe[i],q),"exact challenge embedding");for(const w of W)ok(nearest(dot(w,p,q),q,g,m)===ts[j],"distinct witness same digit");recovered.push(nearest(dot(W[0],p,q),q,g,m))}ok(undigits(recovered,m)===BigInt(Z),"one uniform precommitted pad")}}
  const Q=2n**20n,G=1536n,H=128n,N=4096n,D=32n,M=Q/G;ok(Q%G!==0n&&G%H===0n&&(G/H)*N<Q,"reference parameters");ok(M===682n&&M**27n<2n**256n&&M**28n>=2n**256n,"exact 28 columns");ok(Q-(M-1n)*G>=G,"cyclic guard");ok(G*G*25n===225n*8n*H*256n,"exact Gaussian exponent");
  // Rational certificate exp(694/1000)>2 using the positive degree-four Taylor partial sum.
  let numerator=0n,denominator=1n,pow=1n,fact=1n;const gcd=(a,b)=>{while(b){[a,b]=[b,a%b]}return a};
  for(let i=0;i<=4;i++){if(i){pow*=694n;fact*=BigInt(i)}const d=1000n**BigInt(i)*fact;numerator=numerator*d+pow*denominator;denominator*=d;const f=gcd(numerator,denominator);numerator/=f;denominator/=f}
  ok(numerator>2n*denominator&&324n*694n<225n*1000n,"elementary exp bound");
  let bin=1n;for(let i=1n;i<=H;i++)bin=bin*(N-i+1n)/i;
  ok(bin>2n**816n&&bin<2n**817n&&Q**D===2n**640n,"binomial/Q exact bound");
  ok(2n*28n<2n**6n&&N*28n<2n**17n,"two coupling/exponent counts");
  return {status:"ok",checks,radix:m,columns:28,previous_columns:29,one_vector_saved_bytes:10240,
          noise_first_term:"<2^-141",noise_coupling:"<2^-139",honest_all_witness_failure:"<2^-138",
          conditioned_true_failure:"<2^-137",security:"only restricted reference; QPT LWE/natives uninstantiated"};
}
process.stdout.write(JSON.stringify(checkNondivisorRadix())+'\n');
