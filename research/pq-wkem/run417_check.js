'use strict';
// Run 417 finite algebra only: no cryptographic security claim.
let assertions=0;
function ok(v,s){assertions++;if(!v)throw Error(s)}
function parity(n){let p=0;while(n){p^=1;n&=n-1}return p}
function rank(v){let b={};for(let x of v){while(x){let h=31-Math.clz32(x);if(b[h]===undefined){b[h]=x;break}x^=b[h]}}return Object.keys(b).length}
let predictors=0, listSizes={};
for(let n=3;n<=8;n++){
 const N=1<<n;
 for(let k=0;k<N;k++){
  const B=r=>parity(r&k)^Number((r&3)===3);
  let correct=0;
  for(let r=0;r<N;r++)correct+=Number(B(r)===parity(r&k));
  ok(correct*4===3*N,'predictor bias');
  let heavy=[];
  for(let candidate=0;candidate<N;candidate++){
   let corr=0;
   for(let r=0;r<N;r++)corr+=(B(r)===parity(r&candidate))?1:-1;
   if(corr*2>=N)heavy.push(candidate);
  }
  ok(heavy.includes(k),'GL heavy candidate missing');
  ok(heavy.length<=4,'Parseval list bound');
  listSizes[heavy.length]=(listSizes[heavy.length]||0)+1;
  predictors++;
 }
}
let exhaustive={};
for(const [n,t] of [[2,4],[3,4],[3,5]]){
 let matrices=0,separated=0;
 for(let z=0;z<(1<<(n*t));z++){
  let rows=[];
  for(let i=0;i<t;i++)rows.push((z>>(i*n))&((1<<n)-1));
  const image=new Set();
  for(let k=0;k<(1<<n);k++){
   let val=0;
   for(let i=0;i<t;i++)val|=parity(rows[i]&k)<<i;
   image.add(val);
  }
  let cols=[];
  for(let j=0;j<n;j++){
   let val=0;
   for(let i=0;i<t;i++)val|=((rows[i]>>j)&1)<<i;
   cols.push(val);
  }
  const all=(1<<t)-1, inside=image.has(all);
  ok((rank([...cols,all])===rank(cols))===inside,'rank/image');
  for(const a of image)ok(image.has(a^all)===inside,'coset');
  separated+=Number(!inside);matrices++;
 }
 exhaustive['n'+n+'_t'+t]={matrices,separated,tv:separated/matrices};
}
console.log(JSON.stringify({run:417,check:'GL predictor and reused-key rank cosets',predictors,listSizes,exhaustive,assertions,security:'toy identities only'},null,2));
