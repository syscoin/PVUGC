'use strict';
// Run 706 independent finite matrix census and public-polynomial coupling.
// Not a QPT proof or a hard-true key-only extractor.
const q=3,N=3,s=2,K=1;let checks=0;
function ok(x,m){if(!x)throw new Error(m);checks++}
function mod(x){return ((x%q)+q)%q}
function rank(A){let a=A.slice(),r=0;for(let c=0;c<N;c++){
 let p=-1;for(let i=r;i<N;i++)if(a[i*N+c]){p=i;break}if(p<0)continue;
 for(let j=0;j<N;j++){let t=a[r*N+j];a[r*N+j]=a[p*N+j];a[p*N+j]=t}
 const v=a[r*N+c],inv=v===1?1:2;
 for(let j=0;j<N;j++)a[r*N+j]=mod(inv*a[r*N+j]);
 for(let i=0;i<N;i++)if(i!==r){const t=a[i*N+c];for(let j=0;j<N;j++)a[i*N+j]=mod(a[i*N+j]-t*a[r*N+j])}
 if(++r===N)break}return r}
const eye=Array.from({length:N*N},(_,k)=>Number(k%N===Math.floor(k/N)));
const M=[1,1,1,2,2,2,0,0,0];ok(rank(M)<=N-s,'valid rank margin');
function C(u,Q){const r=mod(u*u-u);return M.map((x,j)=>mod(x+K*eye[j]+r*Q[j]))}
let low=0;const mapped=new Set();const count=q**(N*N);
for(let a=0;a<count;a++){
 let x=a,Q=[];for(let j=0;j<N*N;j++){Q.push(x%q);x=Math.floor(x/q)}
 const c0=C(0,Q),c1=C(1,Q),c2=C(2,Q);
 ok(c0.every((v,j)=>v===c1[j]),'both valid witnesses share public matrix rank margin');
 ok(rank(c0.map((v,j)=>mod(v-K*eye[j])))<=N-s,'valid nullity >=s');
 const shifted=c2.map((v,j)=>mod(v-K*eye[j]));mapped.add(shifted.join(','));
 if(rank(shifted)<=N-s)low++;
}
ok(mapped.size===count,'invalid residual makes complete evaluated matrix uniform');
ok(low===339,'exact q=3,N=3,deficiency2 count');
// Bound is Gaussian[3,2]_3 * 3^(-3*2) = 13/729, while count/3^9 = 339/19683.
ok(low*729<=13*count,'s-subspace union bound');
console.log(JSON.stringify({run:706,assertions:checks,field:3,dimension:3,deficiency:2,
 uniform_invalid_matrices:mapped.size,possible_matrices:count,
 low_rank_count:low,exact_low_rank_probability:low/count,
 complete_public_coefficients:true,hard_true_key_only_extraction_proved:false}));
