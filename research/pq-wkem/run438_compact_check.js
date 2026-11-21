// Run 438: exact S4 endpoint-pin orbit check, Node.js standard library only.
'use strict';
const P=[];for(let a=0;a<4;a++)for(let b=0;b<4;b++)for(let c=0;c<4;c++)for(let d=0;d<4;d++)if(new Set([a,b,c,d]).size===4)P.push([a,b,c,d]);
const I=[0,1,2,3],cases=[I,[0,1,3,2],[1,0,2,3],[0,2,1,3]];let checks=0;
function ok(x){checks++;if(!x)throw Error('failed '+checks)}
function mul(a,b){return b.map(i=>a[i])}
function inv(a){return a.map((_,i)=>a.indexOf(i))}
function law(t){let M=new Map();for(const u0 of P)for(const u1 of P)for(const u2 of P){let g1=mul(u1,inv(u0)),g2=mul(u2,mul(t,inv(u1))),A=[u0[0],u0[1]],B=[u2[0],u2[2]],G=mul(g2,g1),pattern=[+(G[A[0]]===B[0]),+(G[A[0]]===B[1]),+(G[A[1]]===B[0]),+(G[A[1]]===B[1])],expected=[+(t[0]===0),+(t[0]===2),+(t[1]===0),+(t[1]===2)];ok(pattern.every((x,i)=>x===expected[i]));let k=JSON.stringify([g1,g2,A,B]);M.set(k,(M.get(k)||0)+1)}ok([...M.values()].reduce((a,b)=>a+b,0)===24**3);ok(new Set(M.values()).size===1);return M}
const d=cases.map(law);ok(d[0].size===13824&&d[1].size===13824&&d[2].size===13824&&d[3].size===6912);ok(d[0].size===d[1].size&&[...d[0]].every(([k,v])=>d[1].get(k)===v));ok([...d[0].keys()].every(k=>!d[2].has(k)&&!d[3].has(k)));
console.log(JSON.stringify({run:438,status:'PASS',assertions:checks,group:'S4',supports:d.map(x=>x.size),same_incidence_equal:true,different_incidence_disjoint:true,scope:'exact finite forest endpoint-pin theorem; no PQ WKEM'}));
