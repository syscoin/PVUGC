// R87 exact bounded checker. Run with Node.js or the connected V8 console.
// Finite algebra/test fixtures only; no PQ security, no cryptographic native signature.
"use strict";
let assertions=0;
const checks={two_universal_pairs:0,lhl_histograms:0,openings:0,bit_decodings:0,full_view_checks:0,negative_controls:0};
function ok(v,msg){assertions++;if(!v)throw Error("assertion "+assertions+": "+msg);}
function cart(vals,k){let a=[[]];for(let i=0;i<k;i++){let n=[];for(const x of a)for(const y of vals)n.push([...x,y]);a=n;}return a;}
function mod(x,q){return ((x%q)+q)%q;}
function mul(D,r,q,d){let out=Array(d).fill(0);for(let i=0;i<r.length;i++)for(let j=0;j<d;j++)out[j]=mod(out[j]+D[i*d+j]*r[i],q);return out;}
const q=5,m=2,d=2,Rs=cart([-1,0,1],m),Ds=cart([0,1,2,3,4],m*d);
for(let i=0;i<Rs.length;i++)for(let j=i+1;j<Rs.length;j++){
 let equal=0;
 for(const D of Ds){
  const a=mul(D,Rs[i],q,d),b=mul(D,Rs[j],q,d);
  if(a.every((v,k)=>v===b[k]))equal++;
 }
 ok(equal===Ds.length/(q**d),"exact odd-q two-universal collisions");
 checks.two_universal_pairs++;
}
const badDs=cart([0,1,2,3],2);
let badEqual=0;
for(const D of badDs)if(mul(D,[-1,0],4,1)[0]===mul(D,[1,0],4,1)[0])badEqual++;
ok(badEqual===8 && badEqual>badDs.length/4,"even modulus fails at difference 2");
checks.negative_controls++;
function census(domain){
 const q=5,m=4,Ds=cart([0,1,2,3,4],m),Rs=cart(domain,m);
 let mean=0;
 for(const D of Ds){
  const hist=Array(q).fill(0);
  for(const r of Rs)hist[mul(D,r,q,1)[0]]++;
  const tv=hist.reduce((s,v)=>s+Math.abs(v/Rs.length-1/q),0)/2;
  mean+=tv;ok(tv>=0&&tv<=1,"TV bounds");checks.lhl_histograms++;
 }
 mean/=Ds.length;
 const bound=.5*Math.sqrt(q/Rs.length);
 ok(mean<=bound+1e-12,"leftover-hash upper bound");
 return {mean_tv:mean,bound,hash_keys:Ds.length,input_count:Rs.length};
}
const ternary=census([-1,0,1]),binary=census([0,1]);
ok(ternary.mean_tv<binary.mean_tv,"ternary mean TV smaller at identical m");
let state=0x92a1b54f;
function rnd(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;}
function hashFixture(v){const s=JSON.stringify(v);let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619);}return h>>>0;}
function padFixture(bits,n){let x=hashFixture(bits)||1;const out=[];for(let i=0;i<n;i++){x^=x<<13;x^=x>>>17;x^=x<<5;out.push(x&255);}return out;}
function metric(x,a,q){return Math.min(mod(x-a,q),mod(a-x,q));}
const qq=257,mm=8,ell=3,seedLen=24,Delta=128;
for(let trial=0;trial<64;trial++){
 // First column deliberately zero to construct three distinct valid ORIGINAL
 // witnesses; NOT an honestly generated secure LWE key distribution.
 const A=Array.from({length:mm},()=>[0,1+rnd()%250]);
 const S=Array.from({length:ell},()=>[rnd()%qq,rnd()%qq]);
 const E=Array.from({length:mm},()=>Array.from({length:ell},()=>Number(rnd()%3)-1));
 const B=Array.from({length:mm},(_,i)=>Array.from({length:ell},(_,j)=>mod(A[i][1]*S[j][1]+E[i][j],qq)));
 const bits=Array.from({length:seedLen},()=>rnd()%2);
 const native=Array.from({length:32},()=>rnd()%256);
 const pads=padFixture(bits,48),dsig=native.map((v,i)=>v^pads[i]),check=pads.slice(32);
 const groups=[];
 for(let g=0;g<Math.ceil(seedLen/ell);g++){
  const r=Array.from({length:mm},()=>[-1,0,1][rnd()%3]);
  const u=[0,1].map(j=>mod(A.reduce((s,row,i)=>s+row[j]*r[i],0),qq));
  const v=Array.from({length:ell},(_,j)=>mod(B.reduce((s,row,i)=>s+row[j]*r[i],0)+Delta*bits[g*ell+j],qq));
  groups.push({u,v});
 }
 const ctx={relation:"toy vector LWE relation",claim:"tx#"+trial,branch:"challenge"};
 const CK=hashFixture({check,dsig,groups,ctx});
 const Aux=hashFixture({check,CK,dsig,groups,ctx});
 for(const offset of [0,1,2]){
  const ss=S.map(([s1,s2])=>[mod(s1+offset,qq),s2]);
  const opened=[];
  for(let g=0;g<groups.length;g++)for(let j=0;j<ell;j++){
   const {u,v}=groups[g];
   const z=mod(v[j]-ss[j][0]*u[0]-ss[j][1]*u[1],qq);
   const bit=metric(z,Delta,qq)<metric(z,0,qq)?1:0;
   opened.push(bit);
   ok(bit===bits[g*ell+j],"every valid ORIGINAL witness gets same bit");
   checks.bit_decodings++;
  }
  ok(JSON.stringify(opened)===JSON.stringify(bits),"same seed");
  const pp=padFixture(opened,48),recovered=dsig.map((v,i)=>v^pp[i]),cc=pp.slice(32);
  ok(JSON.stringify(recovered)===JSON.stringify(native),"same native capability test bytes");
  ok(hashFixture({check:cc,dsig,groups,ctx})===CK &&
     hashFixture({check:cc,CK,dsig,groups,ctx})===Aux,"same checking-key/aux fixture");
  checks.openings++;checks.full_view_checks++;
 }
}
const n=256,l=16,lambda=128,qReal=65521,k=11008;
const req=(n+l)*Math.log2(qReal)+2*lambda+2;
const m2=Math.ceil(req),m3=Math.ceil(req/Math.log2(3));
const eps2=2**(-1+.5*((n+l)*Math.log2(qReal)-m2));
const eps3=2**(-1+.5*((n+l)*Math.log2(qReal)-m3*Math.log2(3)));
ok(m3<m2&&eps2<=2**(-lambda-2)&&eps3<=2**(-lambda-2),"parameter inequality");
const result={run:"R87-TERNARY-ODD-MODULUS-PACKING-20261105",
status:"RESTRICTED_CONSTRUCTION_ADVANCE_NOT_GENERIC_WKEM",assertions,checks,
example:{q:qReal,n,ell:l,lambda,m_binary:m2,m_ternary:m3,
m_reduction_percent:100*(m2-m3)/m2,
eps_binary:eps2,eps_ternary:eps3,
full_pk_16bit_bytes_binary:2*m2*(n+l),
full_pk_16bit_bytes_ternary:2*m3*(n+l),
ciphertext_Zq_elements:Math.ceil(k/l)*n+k,
max_error_beta_binary:Math.floor((qReal/4-1)/m2),
max_error_beta_ternary:Math.floor((qReal/4-1)/m3)},
ternary_census:ternary,binary_census:binary,
even_q_negative_collision_count:badEqual,
negative_universal_expected:badDs.length/4,
caveats:"Toy checksums/pad are NOT cryptographic. LWE not QPT calibrated. Generic ORIGINAL recovery extraction remains unproved."};
const emit=typeof text==="function"?text:console.log;
emit(JSON.stringify(result,null,2));
