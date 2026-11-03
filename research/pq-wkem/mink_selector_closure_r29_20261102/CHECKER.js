// Independently implemented exact integer Boolean-quotient verifier for R29.
const F=[[[3,0],[1,1],[2,0]],[[0,1],[3,1],[2,1]],[[2,1],[0,1],[3,0]],[[3,1],[2,0],[1,0]],[[1,1],[0,0],[3,1]],[[1,0],[2,1],[0,0]],[[2,0],[3,0],[1,0]],[[1,1],[2,0],[3,1]],[[2,1],[3,0],[0,0]]];
const G=[[[0,1],[1,1],[2,1]],[[0,0],[1,1],[2,1]],[[1,0],[2,1],[0,1]]];
const unit=()=>new Map([[0,1]]), variable=i=>new Map([[1<<i,1]]);
function plus(...args){const d=new Map();for(const p of args)for(const [m,c] of p){const x=(d.get(m)||0)+c;if(x)d.set(m,x);else d.delete(m)}return d}
const scale=(p,c)=>new Map([...p].map(([m,v])=>[m,v*c]).filter(([,v])=>v));
function times(a,b){const d=new Map();for(const [i,u] of a)for(const [j,v] of b){const k=i|j;d.set(k,(d.get(k)||0)+u*v)}return new Map([...d].filter(([,v])=>v))}
function f(cl){let z=unit();for(const [i,pos] of cl)z=times(z,pos?plus(unit(),scale(variable(i),-1)):variable(i));return z}
const eq=(a,b)=>a.size===b.size&&[...a].every(([m,v])=>b.get(m)===v);
let checked=0;
function ck(cond,where){checked++;if(!cond)throw Error(where)}
const cert=F.map((_,j)=>[j,0,1]).concat([[4,1<<2,-1],[5,1<<3,-1]]);
const all=F.map(f);let expression=new Map();
for(const [j,m,c] of cert)expression=plus(expression,scale(times(new Map([[m,1]]),all[j]),c));
ck(eq(expression,unit()),'explicit integer identity for original F');
function branch(offset,t,aux,isF){const sel=isF?plus(unit(),scale(variable(t),-1)):variable(t);const cs=[];let derived=new Map();
 for(let j=0;j<F.length;j++){
  const abc=F[j].map(([v,p])=>[v+offset,p]);const [a,b,c]=abc;
  const g1=f([[t,isF?1:0],a,[aux+j,1]]),g2=f([[aux+j,0],b,c]);cs.push(g1,g2);
  const x=f([a]),y=f([b]),z=f([c]);
  ck(eq(plus(times(times(y,z),g1),times(times(sel,x),g2)),times(sel,f(abc))),'selector gadget '+isF+' clause '+j);
 }
 for(const [j,m0,c] of cert){const m=m0<<offset;const abc=F[j].map(([v,p])=>[v+offset,p]);const [a,b,c0]=abc;
  const x=f([a]),y=f([b]),z=f([c0]);
  derived=plus(derived,scale(times(new Map([[m,1]]),plus(times(times(y,z),cs[2*j]),times(times(sel,x),cs[2*j+1]))),c));
 }
 ck(eq(derived,sel),'transported branch refutation');
 return derived;
}
const t=8, left=branch(0,t,9,true),right=branch(4,t,18,false);
ck(eq(plus(left,right),unit()),'OR of two FALSE original formulas publicly certified');
// Independent check of 80 distinct valid original-witness extensions for R28's TRUE G.
const sat=(cs,assign)=>cs.every(cl=>cl.some(([v,p])=>assign[v]===p));
let good=0;
for(let xb=0;xb<16;xb++)for(let yb=0;yb<8;yb++){
 const X=[0,1,2,3].map(i=>(xb>>i)&1),Y=[0,1,2].map(i=>(yb>>i)&1);
 if(!sat(G,Y))continue;
 const as=[...X,1,...Y,...F.map(cl=>+cl.slice(1).some(([v,p])=>X[v]===p)),...G.map(cl=>+cl.slice(1).some(([v,p])=>Y[v]===p))];
 const clauses=[];
 for(let j=0;j<F.length;j++){const [a,b,c]=F[j];clauses.push([[4,1],a,[8+j,1]],[[8+j,0],b,c])}
 for(let j=0;j<G.length;j++){const [a,b,c]=G[j].map(([v,p])=>[v+5,p]);clauses.push([[4,0],a,[17+j,1]],[[17+j,0],b,c])}
 ck(sat(clauses,as),'distinct actual ORIGINAL witness');good++;
}
ck(good===80,'OR true witnesses total');
console.log(JSON.stringify({id:'R29-INDEPENDENT-JS',pass:true,assertions:checked,refutation_degree:1,source_mask_degree:3,OR_true_witnesses:good,certificate_identity:'exact integer squarefree quotient'},null,2));
