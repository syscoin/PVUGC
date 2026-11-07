'use strict';
let assertions=0;
function ck(v,m){assertions++;if(!v)throw Error(m)}
const cases=[];
for(let t=1;t<=8;t++){
 let pos=0,neg=0,valid=0,queries=0;
 for(let x=0;x<256;x++){
  const a=Array(t).fill(false);
  for(let w=0;w<8;w++)if((x>>>w)&1){a[w%t]=true;valid++;ck(a[w%t], 'complete')}
  let got=false;
  for(let u=0;u<t;u++){queries++;if(a[u]){got=true;break}}
  ck(got===(x!==0),'enumeration');
  if(got)pos++;else neg++;
 }
 ck(pos===255&&neg===1,'all cases');
 cases.push({selectors:t,trueStatements:pos,falseStatements:neg,validWitnessChecks:valid,publicQueries:queries});
}
ck(cases.length===8,'coverage');
console.log(JSON.stringify({run:492,assertions,cases,scope:'Exhaustive toy release-slot enumeration; not a WKEM or QPT test.'},null,2));
