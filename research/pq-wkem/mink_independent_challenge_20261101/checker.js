(function(){
"use strict";
const A=[94,11,14,50,7,88,5],q=101,B=1,gamma=33;
const K4=[[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]];
const C4=[[0,1],[1,2],[2,3],[3,0]];
let state=0xD73C2026>>>0,checks=0;
function rand(){state=(Math.imul(state,1664525)+1013904223)>>>0;return state;}
function ck(ok){checks++;if(!ok)throw Error("IVEC check #"+checks);}
function com(b){const s=rand()%q,e=A.map(()=>rand()%3-1);const c=A.map((a,j)=>(a*s+e[j]+(j===0?gamma*b:0))%q);return {c,open:{b,s,e}};}
function verify(C,o){if(![0,1,2].includes(o.b)||!Number.isInteger(o.s)||o.s<0||o.s>=q||o.e.length!==A.length||!o.e.every(z=>z>=-B&&z<=B))return false;return A.every((a,j)=>C[j] === ((a*o.s+o.e[j]+(j===0?gamma*o.b:0))%q));}
const colorings=[];
for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++){
  const col=[a,b,c,d],bad=K4.filter(e=>col[e[0]]===col[e[1]]).length;
  ck(bad>=1);colorings.push({col,bad});
}
ck(colorings.length===81);
ck(Math.min(...colorings.map(o=>o.bad))===1);
const best=colorings.find(o=>o.bad===1).col;
const exact={};
for(let ell=1;ell<=4;ell++){
  const total=6**ell;let accepted=0;
  for(let n=0;n<total;n++){
    let x=n,ok=true;
    for(let r=0;r<ell;r++){const [u,v]=K4[x%6];x=Math.floor(x/6);if(best[u]===best[v])ok=false;}
    if(ok)accepted++;
  }
  ck(accepted===5**ell);
  exact[String(ell)]={accepted,total,fraction:accepted+"/"+total};
}
const proper=[0,1,0,1];let instances=0;
const tags=new Set();
for(let i=0;i<4;i++)for(let j=0;j<4;j++)if(j!==i)for(let r=0;r<6;r++){
  const tag="claim|utxo|vk|capsules|session001|"+i+"|"+j+"|"+r;
  ck(!tags.has(tag));tags.add(tag);
  const offset=rand()%3;
  const vertex=proper.map(z=>com((z+offset)%3));
  const [u,v]=C4[rand()%4];
  ck(verify(vertex[u].c,vertex[u].open));
  ck(verify(vertex[v].c,vertex[v].open));
  ck(vertex[u].open.b!==vertex[v].open.b);
  const bad={...vertex[u].open,b:(vertex[u].open.b+1)%3};
  ck(!verify(vertex[u].c,bad));
  instances++;
}
ck(instances===72);
return {run_id:"MINK-IVEC-2026-11-01-T17",scope:"conditional one-honest-verifier soundness, NOT zero knowledge or WKEM",test:"deterministic standard-JavaScript toy arithmetic; no hardness experiment",assertion_events:checks,false_graph_assignments:81,exact_acceptance:exact,true_proof_instances:instances,parameters:{n_party:4,graph_k4_edges:6,ell_max:4,q:101,n_lwe:1,m_lwe:7,B:1}};
})()
