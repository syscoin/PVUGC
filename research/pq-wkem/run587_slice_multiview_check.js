// Run 587 — deterministic finite checker, Node-compatible, no dependencies.
// Formula and attack scope in RUN587_HAMMING_SLICE_MULTI_VIEW.md.
function verify(){
let tests=0; const chk=(v,m)=>{tests++;if(!v)throw Error(m);};
const choose=(n,k)=>{let x=1;for(let i=1;i<=k;i++)x=x*(n+1-i)/i;return x;};
const bound=(m,q)=>{let sum=0;for(let k=0;k<=m;k++){let N=choose(m,k);sum+=N/(2**m)*Math.min(1,Math.sqrt((q-1)/N));}return sum;};
const fixed=[];
for (let [m,q] of [[3,5],[4,7],[5,7],[6,5]]){
 const H=(q-1)/2, groups=Array.from({length:m+1},()=>[]);
 for(let mask=0;mask<(1<<m);mask++){let r=Array.from({length:m},(_,i)=>(mask>>i)&1);groups[r.reduce((a,b)=>a+b,0)].push(r);}
 let total=0;
 for(let code=0;code<q**m;code++){let b=[],v=code;for(let i=0;i<m;i++){b.push(v%q);v=Math.floor(v/q);}
  let tally=0;
  for(let slice of groups){let hist=Array(q).fill(0);
    for(let r of slice){let t=0;for(let i=0;i<m;i++)t+=b[i]*r[i];hist[t%q]++;}
    for(let y=0;y<q;y++)tally+=Math.abs(hist[y]-hist[(y-H+q)%q]);
  }
  chk(tally>=0&&tally<=2*(1<<m),"bad exact TV");total+=tally;
 }
 let denominator=2*(2**m)*(q**m), observed=total/denominator, upper=bound(m,q);
 chk(observed<=upper+1e-12,"average TV bound");fixed.push({m,q,exact_average_tv:observed,upper,keys:q**m});
}
const m=48,q=257,H=128,B=1;chk(m*B<(q-1)/4,"correctness threshold");
const b=Array.from({length:m},(_,i)=>(17+37*i)%q);
const valid=(s,b)=>b.every(bi=>Math.min((bi-s+q)%q,(s-bi+q)%q)<=1);
chk(!valid(0,b)&&!valid(1,b),"target unexpectedly true");
let state=5872026>>>0;const bit=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state&1;};
let recovered=0;
for(let j=0;j<128;j++){
 const r=Array.from({length:m},()=>bit()),u=r.reduce((a,b)=>a+b,0),mu=bit();
 let v=(b.reduce((acc,a,i)=>acc+a*r[i],0)+H*mu)%q,found=[];
 for(let i=0;i<m;i++){
  const ei=Array.from({length:m},(_,k)=>Number(k===i));
  chk(valid(0,ei)&&valid(1,ei),"auxiliary witnesses");
  const mui=bit(),vi=r[i]+H*mui;
  chk(vi===0||vi===1||vi===H||vi===H+1,"aux range");
  const ri=(vi===1||vi===H+1)?1:0;
  const guessMui=(vi===H||vi===H+1)?1:0;
  chk(ri===r[i]&&guessMui===mui,"failed nonce extraction");
  found.push(ri);
 }
 const residue=(v-b.reduce((acc,a,i)=>acc+a*found[i],0)%q+q)%q;
 chk(residue===0||residue===H,"target offset wrong");
 chk(Number(residue===H)===mu,"target secret recovery");
 recovered++;
}
return {run:587,js_assertions:tests,finite_exact_tv:fixed,m48_q257_bound:bound(48,257),true_statement_probability_upper:2*(3/257)**48,aux_capsules:48,valid_witnesses_each:2,target_bits_recovered:recovered,target_original_false:true,coin_reuse_across_capsules:true,practical_wkem:false};
}
const result=verify();
if(typeof console!=="undefined")console.log(JSON.stringify(result,null,2));
