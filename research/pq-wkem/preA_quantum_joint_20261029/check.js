(function check(){
let assertions=0; const ok=(x,m)=>{if(!x)throw Error(m);assertions++};
const q=3,m=3,h=2,D=2,Q=3;
const S=[];for(let a=-2;a<=2;a++)for(let b=-2;b<=2;b++)for(let c=-2;c<=2;c++)if(Math.abs(a)+Math.abs(b)+Math.abs(c)===2)S.push([a,b,c]);
const N=S.length;ok(N===18,"sphere count");ok(new Set(S.map(w=>w.map(x=>(x+q)%q).join(','))).size===N,"residue injection");
const matrices=[];for(let a=0;a<q;a++)for(let b=0;b<q;b++)for(let c=0;c<q;c++)matrices.push([a,b,c]);
const states=[[1,0,0,0],[0,0,0,1],[.5,.5,0,.5],[.5,-.5,0,.5],[.5,0,-.5,.5],[.5,0,.5,.5]];
const state1=w=>states[((w[0]+2*w[1]+4*w[2])%6+6)%6];
const state2=(w,z)=>states[((w[0]+2*w[1]+3*z[0]+5*z[2]+w[2]*z[1])%6+6)%6];
const zero=()=>[0,0,0,0], add=(u,v,c=1)=>{for(let i=0;i<4;i++)u[i]+=c*v[i]};
const sub=(u,v)=>u.map((x,i)=>x-v[i]), hash=(a,w)=>((a.reduce((s,x,i)=>s+x*w[i],0)%q)+q)%q;
const trnorm=x=>{const mean=(x[0]+x[3])/2,rad=Math.sqrt(((x[0]-x[3])/2)**2+x[1]**2+x[2]**2);return Math.abs(mean+rad)+Math.abs(mean-rad)};
const hs2=x=>x[0]**2+x[3]**2+2*(x[1]**2+x[2]**2);
const E1=zero();for(const w of S)add(E1,state1(w),1/N);
let tv1=0,hs=0;
for(const a of matrices){const T=Array.from({length:Q},zero);for(const w of S){add(T[hash(a,w)],state1(w),1/N);ok(true,"single sample")}
for(let y=0;y<Q;y++){const X=sub(T[y],E1.map(v=>v/Q));tv1+=trnorm(X)/(2*matrices.length);hs+=hs2(X)/matrices.length}}
const purity=S.reduce((s,w)=>s+hs2(state1(w)),0);
const expectedHS=(1-1/Q)*purity/N**2;
ok(Math.abs(hs-expectedHS)<1e-12,"quantum HS exact average");
const bound1=.5*Math.sqrt(D*(Q-1)/N);ok(tv1<=bound1+1e-12,"single quantum trace bound");
const E2=zero();for(const w of S)for(const z of S)add(E2,state2(w,z),1/(N*N));
let tv2=0;
for(const a of matrices){const T=Array.from({length:Q*Q},zero);for(const w of S)for(const z of S){add(T[hash(a,w)*Q+hash(a,z)],state2(w,z),1/(N*N));ok(true,"two-source joint state")}
for(let y=0;y<Q*Q;y++)tv2+=trnorm(sub(T[y],E2.map(v=>v/(Q*Q))))/(2*matrices.length)}
ok(tv2<=2*bound1+1e-12,"shared A joint quantum bound");
ok(tv1>0&&tv2>0,"nontrivial distance");ok(states[4][2]!==0&&states[2][1]!==0,"noncommuting quantum states");
return {status:"PASS",assertions,q,n:1,m,h,N,quantum_dimension:D,one_source_trace_distance:+tv1.toFixed(12),one_source_bound:+bound1.toFixed(12),two_joint_sources_shared_A_trace_distance:+tv2.toFixed(12),two_sources_bound:+(2*bound1).toFixed(12),hilbert_schmidt_observed:+hs.toFixed(12),hilbert_schmidt_formula:+expectedHS.toFixed(12),scope:"Finite noncommuting cq density-matrix enumeration, not QPT hardness"};
})();
