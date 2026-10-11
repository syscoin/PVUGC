'use strict';
const assert=require('node:assert/strict');let assertions=0;
const ck=(b)=>{assert.ok(b);assertions++};
const mod=(v,q)=>(v%q+q)%q;
function rank(A,q){let M=A.map(r=>r.slice()),t=M.length,n=M[0].length,k=0;
 for(let j=0;j<n&&k<t;j++){let p=k;while(p<t&&mod(M[p][j],q)===0)p++;if(p===t)continue;
 [M[k],M[p]]=[M[p],M[k]];let v=1;while(mod(v*M[k][j],q)!==1)v++;
 for(let h=j;h<n;h++)M[k][h]=mod(v*M[k][h],q);
 for(let i=0;i<t;i++)if(i!==k){let c=M[i][j];for(let h=j;h<n;h++)M[i][h]=mod(M[i][h]-c*M[k][h],q)} k++}return k}
function census(q,t,d){let bad=0,full=0;const total=q**(t*(d+1));
 for(let v=0;v<total;v++){let x=v,A=Array.from({length:t},()=>Array(d+1).fill(0));
 for(let i=0;i<t;i++)for(let j=0;j<=d;j++){A[i][j]=x%q;x=Math.floor(x/q)}
 const r=rank(A.map(row=>row.slice(1)),q),accepted=rank(A,q)===r;
 if(r===t){ck(accepted);full++}if(accepted){bad++;let found=false;
 for(let n=0;n<q**d;n++){let s=n,z=[];for(let j=0;j<d;j++){z.push(s%q);s=Math.floor(s/q)}
 if(A.every(row=>mod(row[0]+z.reduce((v,w,j)=>v+row[j+1]*w,0),q)===0)){found=true;break}}
 ck(found)}}return {q,t,d,bad,total,full}}
const cases=[[2,1,1,3],[2,2,2,43],[2,2,3,211],[3,2,2,529],[5,2,1,121]];
const samples=cases.map(([q,t,d,expected])=>{let o=census(q,t,d);ck(o.bad===expected);return o});
console.log(JSON.stringify({run:449,assertions,samples,scope:'finite algebra; no practical or QPT release construction'},null,2));
