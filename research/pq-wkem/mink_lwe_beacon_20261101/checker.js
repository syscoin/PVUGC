const runCheck = function runCheck() {
 let checks=0; const assert=(x,s)=>{if(!x)throw Error(s);checks++};
 const q=101,B=1,A=[94,11,14,50,7,88,5],m=7, gamma=Math.floor(q/3);
 const mod=x=>((x%q)+q)%q;
 const com=(b,s,e)=>A.map((a,j)=>mod(a*s+e[j]+(j===0?gamma*b:0)));
 const seen=new Map();let enumerated=0;
 for(let b=0;b<3;b++)for(let s=0;s<q;s++)for(let t=0;t<3**m;t++){
  let k=t,ee=[];for(let j=0;j<m;j++){ee.push(k%3-1);k=Math.floor(k/3)}
  const c=com(b,s,ee),key=String.fromCharCode(...c),old=seen.get(key);
  assert(old===undefined||old===b,"cross-color collision");seen.set(key,b);enumerated++;
 }
 assert(enumerated===3*q*3**m,"coverage");
 assert(seen.size===enumerated,"unexpected duplicate");
 const log2=Math.log2;const binding=(n,M,Q,D)=>log2(6)+n*log2(Q)+M*(log2(4*D+1)-log2(Q));
 assert(binding(1,7,101,1)<-20,"toy union bound");
 assert(binding(256,1024,4294967291,256)<-128,"illustrative union bound");
 const yesEdges=[[0,1],[1,2],[2,3],[3,0]],colors=[0,1,0,1];
 const permutations=[[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]];
 for(let r=0;r<48;r++){
  const perm=permutations[r%6],e=yesEdges[r%4],Cs=[],Ops=[];
  for(let v=0;v<4;v++){
    const color=perm[colors[v]],s=(13*r+7*v+5)%q,err=A.map((_,j)=>(r+v+j)%3-1);
    const c=com(color,s,err);Cs.push(c);Ops.push({color,s,err});
    assert(JSON.stringify(com(color,s,err))===JSON.stringify(c),"honest open");
  }
  const [u,v]=e;assert(Ops[u].color!==Ops[v].color,"true edge");
  for(const k of [u,v])assert(JSON.stringify(com(Ops[k].color,Ops[k].s,Ops[k].err))===JSON.stringify(Cs[k]),"valid open");
 }
 const K4=[[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]];
 for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++){
  const col=[a,b,c,d];assert(K4.some(([u,v])=>col[u]===col[v]),"K4 inconsistent");
 }
 for(let a=0;a<3;a++)for(let b=0;b<3;b++)if(a!==b){
  const pairs=new Set(permutations.map(p=>`${p[a]}:${p[b]}`));
  assert(pairs.size===6,"opened pair uniform support");
 }
 let rounds=0;while(Math.pow(5/6,rounds)>Math.pow(2,-128)){rounds++;if(rounds>2000)throw Error("bound")}
 assert(rounds===487,"soundness cap");
 return {run:"MINK-BHC-2026-11-01-T16",assertions:checks,enumerated_openings:enumerated,unique_commitment_values:seen.size,toy:{q,n:1,m,B,A},global_binding_log2_bound_toy:binding(1,7,101,1),illustrative_global_binding_log2_bound:binding(256,1024,4294967291,256),k4_rounds_128bit_soundness:rounds,scope:"finite algebraic checks; no quantum security experiment or full WKEM"};
};
console.log(JSON.stringify(runCheck(),null,2));
