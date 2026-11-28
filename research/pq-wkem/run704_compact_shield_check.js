// Run 704: exact full-coefficient false-key masking coupling.
// Standard node, deterministic; q=3 exhaustive and q=101 matrix-polynomial checks.
const assert=require('node:assert/strict');
let checks=0; function req(v,m){assert.ok(v,m);checks++;}
const cube=[[1,-1,-1,1],[0,0,1,-1],[0,1,0,-1],[0,0,0,1]];
function mod(v,q){return ((v%q)+q)%q}
function coeff(k,values,q){
  const a=[k,0,0,0];
  for(let i=0;i<4;i++)for(let j=0;j<4;j++)a[j]+=values[i]*cube[i][j];
  return a.map(v=>mod(v,q));
}
function histogram(k){const hist=new Map();
  for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++){
    const v=coeff(k,[a,b,c,d],3).join(','); hist.set(v,(hist.get(v)||0)+1);
  }
  req(hist.size===81,'every one of 81 public coefficient views appears');
  for(const n of hist.values())req(n===1,'uniform exact full-coefficient distribution');
  return [...hist.entries()].sort((a,b)=>a[0].localeCompare(b[0]));
}
const h0=histogram(0),h1=histogram(1),h2=histogram(2);
req(JSON.stringify(h0)===JSON.stringify(h1),'full transcript K0 vs K1');
req(JSON.stringify(h1)===JSON.stringify(h2),'full transcript K1 vs K2');
// Matrix-valued coupled mask shift, all coefficient slices, not selective evaluations.
const q=101,N=3,identity=Array.from({length:N*N},(_,i)=>i%4===0?1:0);
for(let trial=0;trial<17;trial++){
  const masks=Array.from({length:4},(_,i)=>Array.from({length:N*N},(_,j)=>mod(19*i+11*j+17*trial+7*i*j,q)));
  const K=37,Delta=22,shifted=masks.map(A=>A.map((x,j)=>mod(x-Delta*identity[j],q)));
  for(let j=0;j<N*N;j++){
    const before=coeff(K*identity[j],masks.map(A=>A[j]),q);
    const after=coeff((K+Delta)*identity[j],shifted.map(A=>A[j]),q);
    req(JSON.stringify(before)===JSON.stringify(after),'entire public matrix-polynomial coefficient coupling');
  }
}
// Nonconstant multiplier certificate for (u), (not u or v), (not v):
// (1-u)+u(1-v)+u*v=1; no constant multipliers achieve this.
const r1=[1,-1,0,0],r2=[0,1,0,-1],ur3=[0,0,0,1];
for(let i=0;i<4;i++)req(r1[i]+r2[i]+ur3[i]===(i===0?1:0),'nontrivial degree-one unit certificate');
let foundConstant=false;
for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++){
  const raw3=[0,0,1,0];
  if([0,1,2,3].every(j=>mod(a*r1[j]+b*r2[j]+c*raw3[j],3)===(j===0?1:0)))foundConstant=true;
}
req(!foundConstant,'degree zero impossible in F3');
// Native context and K can be correlated; this result only proves C independent
// of K conditional on hidden independently sampled masks and known base setup.
console.log(JSON.stringify({run:704,assertions:checks,exhaustive_q3_transcripts:81,
  full_public_matrix_coupling_trials:17,nontrivial_degree_one_identity:true,
  complete_public_coefficient_distributions_independent_of_K:true}));
