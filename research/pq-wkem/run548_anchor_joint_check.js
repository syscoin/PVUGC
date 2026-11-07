'use strict';
const P=[];
for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)if(new Set([a,b,c]).size===3)P.push([a,b,c]);
const I=[0,1,2],S=[1,0,2],m=(a,b)=>b.map(i=>a[i]),v=a=>I.map(i=>a.indexOf(i));
const p=(...xs)=>xs.reduceRight((r,a)=>m(a,r),I);
const e=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const ck=(c,msg)=>{if(!c)throw Error(msg)};
const key=x=>JSON.stringify(x),put=(M,x)=>{let k=key(x);M.set(k,(M.get(k)||0)+1)};
const same=(A,B)=>A.size===B.size&&[...A].every(([k,v])=>B.get(k)===v);
let trees=[];
for(let bit=0;bit<2;bit++){
 let all=new Map(),bare=new Map(),left=new Map(),right=new Map();
 for(const a of P)for(const b of P)for(const c of P){
  let x=p(b,v(a)),y=p(c,bit?S:I,v(b));
  ck(e(p(v(c),y,x,a),bit?S:I),'path invariant');
  put(all,[a,c,x,y]);put(bare,[x,y]);put(left,[a,x,y]);put(right,[c,x,y]);
 }
 trees.push({all,bare,left,right});
}
ck(same(trees[0].bare,trees[1].bare),'bare marginal');
ck(same(trees[0].left,trees[1].left),'left marginal');
ck(same(trees[0].right,trees[1].right),'right marginal');
ck(![...trees[0].all.keys()].some(k=>trees[1].all.has(k)),'anchored overlap');
ck(trees[0].all.size===216&&trees[1].all.size===216,'anchored support');
let ss=[];
for(let bit=0;bit<2;bit++){
 let all=new Map(),pairs=[new Map(),new Map(),new Map()];
 for(const a of P)for(const b of P){
  let x=p(b,bit?S:I,v(a)),l=a[0],r=b[0];
  ck((x[l]===r)===(bit===0),'token predicate');
  put(all,[x,l,r]);put(pairs[0],[x,l]);put(pairs[1],[x,r]);put(pairs[2],[l,r]);
 }
 ss.push({all,pairs});
}
ck(ss[0].all.size===18&&ss[1].all.size===36,'token support');
ck(![...ss[0].all.keys()].some(k=>ss[1].all.has(k)),'token overlap');
for(let i=0;i<3;i++)ck(same(ss[0].pairs[i],ss[1].pairs[i]),'token marginal');
function safe(n,edges,anchors,mask){
 let root=Array.from({length:n},(_,i)=>i);
 const find=x=>{while(root[x]!==x)x=root[x];return x};
 for(let i=0;i<edges.length;i++)if(mask&(1<<i)){
  const [u,v]=edges[i],a=find(u),b=find(v);
  if(a===b)return false;root[a]=b;
 }
 const seen=new Set();
 for(const x of anchors){let a=find(x);if(seen.has(a))return false;seen.add(a);}
 return true;
}
function cut(n,edges,anchors){
 let best=edges.length+1;
 for(let m=0;m<(1<<edges.length);m++)if(safe(n,edges,anchors,m)){
  let count=m.toString(2).split('1').length-1;
  best=Math.min(best,edges.length-count);
 }
 return best;
}
const checks=[['path',3,[[0,1],[1,2]],[0,2],1],['diamond',4,[[0,1],[1,3],[0,2],[2,3]],[0,3],2],['diamond_unanchored',4,[[0,1],[1,3],[0,2],[2,3]],[],1],['theta_3anchors',5,[[0,1],[1,4],[0,2],[2,4],[0,3],[3,4]],[0,2,4],4]];
for(const [name,n,edges,anchors,want] of checks)ck(cut(n,edges,anchors)===want,'cut '+name);
console.log(JSON.stringify({run:548,status:'PASS',masks_per_bit_tree:216,unanchored_equal:true,one_anchor_equal:true,two_anchor_supports_disjoint:true,partial_token_triple_support:[18,36],partial_token_supports_disjoint:true,three_pair_marginals_equal:true,cuts:checks.map(x=>[x[0],x[4]])},null,2));
