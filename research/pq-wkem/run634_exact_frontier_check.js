"use strict";
let checks=0, fixtures=0, maxStates=0, seed=63420261019>>>0;
function rnd(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
function sat(formula,a){return formula.every(c=>c.some(([j,b])=>((a>>>j)&1)===b));}
function accepts(formula,s,n,mask,coin){return (s>>>n)===0 && coin!==3 && sat(formula,(s&((1<<n)-1))^mask);}
for(let n=2;n<=8;n++)for(let trial=0;trial<16;trial++){
 const mask=rnd()&((1<<n)-1),target=rnd()&((1<<n)-1),formula=[];
 for(let k=0;k<n+3;k++){
  const vars=[k%n,(k+1)%n,(k+2)%n].filter((v,i,a)=>a.indexOf(v)===i);
  const clause=vars.map(j=>[j,rnd()&1]);
  if(!clause.some(([j,b])=>((target>>>j)&1)===b))clause[0][1]=(target>>>clause[0][0])&1;
  formula.push(clause);
 }
 if(trial%4===0)formula.push([[0,1]],[[0,0]]);
 let numSat=0,numAcc=0;
 for(let a=0;a<(1<<n);a++)if(sat(formula,a))numSat++;
 for(let s=0;s<(1<<(n+2));s++){
  let v=0;for(let coin=0;coin<4;coin++)if(accepts(formula,s,n,mask,coin))v++;
  if(v!==0&&v!==3)throw Error("coin gate");checks++;
  if(v){numAcc++;if(!sat(formula,(s&((1<<n)-1))^mask))throw Error("source");checks++;}
 }
 if(numAcc!==numSat||Boolean(numAcc)!==Boolean(numSat))throw Error("SAT equivalence");
 checks+=2;fixtures++;maxStates=Math.max(maxStates,1<<(n+2));
}
for(let i=1;i<=4;i++)for(let t=1;t<=16;t++){
 const alpha=i/4,miss=Math.pow(1-alpha,t);
 if(!(miss>=0&&miss<=1&&1-miss>=alpha-1e-12))throw Error("retry");
 checks++;
}
return JSON.stringify({run:634,fixtures,checks,maxStates,seed:63420261019,finite_checks:"passed",security_inference:"none"});
