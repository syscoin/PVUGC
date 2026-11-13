'use strict';
// Finite Walsh-graph validation of the sparse-projection conditional attack.
// No quantum hardware, obfuscation security, or deployed native signature.
let checks=0,seed=4692026;
function ck(v,msg){checks++;if(!v)throw Error(msg)}
function rnd(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0}
function pop(v){let n=0;while(v){n++;v&=v-1}return n}
function mul(a,b,n,poly){let c=0;while(b){if(b&1)c^=a;a<<=1;if(a&(1<<n))a^=poly;b>>>=1}return c&((1<<n)-1)}
function pow(a,k,n,poly){let y=1;while(k){if(k&1)y=mul(y,a,n,poly);a=mul(a,a,n,poly);k>>>=1}return y}
function nullone(rows,N){let piv=new Array(N).fill(0),used=new Array(N).fill(false);
for(let x of rows){while(x){let b=31-Math.clz32(x);if(used[b])x^=piv[b];else{used[b]=true;piv[b]=x;break}}}
let free=[];for(let i=0;i<N;i++)if(!used[i])free.push(i);if(free.length!==1)return null;
let val=1<<free[0];for(let b=0;b<N;b++)if(used[b]&&(pop((piv[b]^(1<<b))&val)&1))val^=1<<b;
for(let row of rows)ck(!(pop(row&val)&1),'nullspace');return val}
function run(n,r,poly,delta,M){const Z=1<<n,N=1+n+r,Q=1<<N,lo=n-r;
let P=Array.from({length:Z},(_,z)=>z?pow(z,Z-2,n,poly):0);
ck(new Set(P).size===Z,'field inverse');
let L=Array.from({length:Z},(_,y)=>{let h=y>>>lo,low=y&((1<<lo)-1);return (h<<lo)|((low^(h*h+h+3))&((1<<lo)-1))});
let a=0,b=1<<lo;[L[a],L[b]]=[L[b],L[a]];ck(new Set(L).size===Z,'L permutation');
let affine=true,gen=Array.from({length:n},(_,i)=>L[1<<i]^L[0]);for(let z=0;z<Z;z++){let v=L[0];for(let i=0;i<n;i++)if(z&(1<<i))v^=gen[i];if(v!==L[z]){affine=false;break}}ck(!affine,'nonlinear L');
let fb=P.map(v=>v>>>lo),hb=P.map(v=>L[v]>>>lo),bad=0;
for(let z=0;z<Z;z++)bad+=fb[z]!==hb[z];ck(bad===2,'two sparse defects');
let Mx=0;for(let d=1;d<Z;d++){let count=new Map();for(let z=0;z<Z;z++){let e=fb[z]^fb[z^d];count.set(e,(count.get(e)||0)+1)}for(let v of count.values())Mx=Math.max(Mx,v)}
ck(Mx+2*bad<Z,'positive promised gap');
let graph=new Int32Array(Q),list=[];
for(let bit=0;bit<2;bit++)for(let z=0;z<Z;z++){
let v=bit?hb[z^delta]:fb[z],idx=bit|(z<<1)|(v<<(n+1));graph[idx]=1;list.push(idx)}
let set=new Set(list),p=1|(delta<<1);let ac=shift=>list.reduce((s,z)=>s+(set.has(z^shift)?1:0),0);
ck(ac(p)===2*Z-2*bad,'near graph shift');
for(let h=1;h<Q;h<<=1)for(let j=0;j<Q;j+=h*2)for(let k=j;k<j+h;k++){
let u=graph[k],v=graph[k+h];graph[k]=u+v;graph[k+h]=u-v}
let weights=Array.from(graph,v=>v*v),den=2*Z*Q;
ck(weights.reduce((s,v)=>s+v,0)===den,'Fourier normalization');
for(let j=0;j<60;j++){let q=rnd()&(Q-1),corr=ac(q),even=0;
for(let y=0;y<Q;y++)if(!(pop(y&q)&1))even+=weights[y];
ck(2*even*2*Z===den*(2*Z+corr),'Fourier autocorrelation')}
let succ=0,falseone=0,viol=0;
for(let trial=0;trial<24;trial++){let rows=[];for(let k=0;k<M;k++){
let x=rnd()&(den-1),sum=0,y=0;
for(;y<Q;y++){sum+=weights[y];if(sum>x)break}ck(y<Q,'sampling');rows.push(y);viol+=pop(y&p)&1}
let candidate=nullone(rows,N);if(candidate===p)succ++;else if(candidate!==null)falseone++}
ck(succ>0,'finite sparse defect recovery');ck(falseone===0,'false 1d solution');
let mu=Mx/Z,eta=bad/Z,wrong=(Q-2)*Math.pow((1+mu+eta)/2,M);
return {n,r,projection_defects:bad,eta,mu,gap:1-mu-2*eta,graph_bits:N,samples_per_batch:M,batches:24,correct_recoveries:succ,false_one_dimensional:falseone,measured_parity_violations:viol,lower_bound:Math.max(0,1-M*eta/2-wrong)} }
let cases=[run(7,3,0x83,0x35,63),run(8,4,0x11b,0x53,75),run(9,4,0x211,0x135,85)];
console.log(JSON.stringify({run:469,assertions:checks,algorithm:'exact Walsh graph distribution, simulated measurements, GF2 nullspace',cases},null,2));
