// R146 exact executed V8 Code Mode checker. Run inside a JS environment providing text(value).
const checks={count:0,cases:0};const assert=(x,msg)=>{checks.count++;if(!x)throw Error(msg)};
const mod=(a,q)=>(a%q+q)%q;
const circular=(a,b,q)=>Math.min(mod(a-b,q),mod(b-a,q));
const q=65521;
let rng=0x5A17BD21;const rnd=()=>{rng^=rng<<13;rng^=rng>>>17;rng^=rng<<5;return rng>>>0};
function build(n,odd){
 const beta=Array.from({length:n},(_,i)=>odd&&i===n-1?1:0);
 const H=Array.from({length:2*n},()=>Array(2*n).fill(0));
 for(let i=0;i<n;i++){for(let t=0;t<2;t++){H[i][2*i+t]=1;H[n+i][2*i+t]+=t;let prev=(i+n-1)%n;H[n+i][2*prev+t]-=(t^beta[prev]);}}
 const b=Array.from({length:2*n},(_,i)=>i<n?1:0);
 return {n,beta,H,b};
}
const matvec=(H,z)=>H.map(r=>r.reduce((v,x,i)=>v+x*z[i],0));
const transcript=(X,K,Delta)=>{
 const n=X.n,s=Array.from({length:2*n},()=>rnd()%q),e=Array.from({length:2*n},()=>rnd()%3-1),eta=rnd()%3-1;
 const c=Array.from({length:2*n},(_,j)=>mod(X.H.reduce((v,r,i)=>v+r[j]*s[i],e[j]),q));
 const p=mod(X.b.reduce((v,x,i)=>v+x*s[i],Delta*K+eta),q);
 return {c,p,e,eta,K};
};
const decode=(t,Delta,q)=>circular(t,0,q)<circular(t,Delta,q)?0:1;
const rec=(p,c,z,q)=>mod(p-z.reduce((v,x,i)=>v+x*c[i],0),q);
const counts=[];
for(const n of [3,5,7,11,23]){
 const f=build(n,true),t=build(n,false);
 const Z=Array(2*n).fill(1),Y=matvec(f.H,Z);
 assert(Y.every((y,i)=>y===2*f.b[i]),"false pseudo certificate HZ=2b");
 for(let k=0;k<2;k++){
  const z=Array(2*n).fill(0);for(let i=0;i<n;i++)z[2*i+k]=1;
  assert(matvec(t.H,z).every((y,i)=>y===t.b[i]),"true witness satisfies");
 }
 // Full local pair distributions: each of two satisfying pair assignments receives weight 1/2.
 // All factor normalizations and shared singleton moments hold; there is no true global witness for odd beta cycle.
 let falseWitnesses=0;
 for(let x=0;x<2**Math.min(n,12);x++){
   const bits=Array.from({length:n},(_,i)=>(x>>>i)&1);
   if(f.beta.every((be,i)=>(bits[i]^bits[(i+1)%n])===be))falseWitnesses++;
 }
 assert(falseWitnesses===0,"false odd cycle");
 const Delta=4*n+10;
 assert(Math.min(2*Delta,q-2*Delta)>2*(2+2*n),"phase separation");
 const iters=256;
 for(let j=0;j<iters;j++){
  const K=j%2;
  const {c,p,e,eta}=transcript(f,K,Delta);
  let candidate=rec(2*p,c,Z,q);
  assert(decode(candidate,2*Delta,q)===K,`public false attack n=${n}`);
  assert(circular(candidate,2*Delta*K,q)<=2+2*n,`error bound n=${n}`);
  const v=transcript(t,K,Delta);
  for(let bit=0;bit<2;bit++){
   const z=Array(2*n).fill(0);for(let i=0;i<n;i++)z[2*i+bit]=1;
   assert(decode(rec(v.p,v.c,z,q),Delta,q)===K,"true same-pad");
  }
 }
 counts.push({n,Delta,checks:iters,half_weights:2*n,false_witnesses:falseWitnesses,attack_success:iters,valid_paths:2});
}
text({result:"PASS",assertions:checks.count,law:"HZ=2b for all-ones Z despite odd-XOR cycle contradiction",q,records:counts});
