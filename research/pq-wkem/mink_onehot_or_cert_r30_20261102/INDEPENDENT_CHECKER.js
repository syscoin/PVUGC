'use strict';
// Independent polynomial and exhaustive one-hot validation. Exact integer arithmetic.
// Validate the R29 certificate with the exact source ordering, not the independent F above.
const R29=[[[3,0],[1,1],[2,0]],[[0,1],[3,1],[2,1]],[[2,1],[0,1],[3,0]],[[3,1],[2,0],[1,0]],[[1,1],[0,0],[3,1]],[[1,0],[2,1],[0,0]],[[2,0],[3,0],[1,0]],[[1,1],[2,0],[3,1]],[[2,1],[3,0],[0,0]]];
let tests=0;
function assert(ok,msg){tests++;if(!ok)throw Error(msg)}
const P0=()=>new Map(),P1=()=>new Map([[0n,1]]),V=i=>new Map([[1n<<BigInt(i),1]]);
const add=(...ps)=>{const q=new Map();for(const p of ps)for(const [k,v] of p)q.set(k,(q.get(k)||0)+v);return new Map([...q].filter(([k,v])=>v!==0))};
const sc=(p,c)=>new Map([...p].filter(([k,v])=>v*c).map(([k,v])=>[k,v*c]));
const sub=(a,b)=>add(a,sc(b,-1));
const mul=(p,q)=>{const o=new Map();for(const [a,c] of p)for(const [b,d] of q)o.set(a|b,(o.get(a|b)||0)+c*d);return new Map([...o].filter(([k,v])=>v!==0))};
const not=p=>sub(P1(),p);
const fail=(cl)=>cl.reduce((p,[v,b])=>mul(p,b?not(V(v)):V(v)),P1());
const equal=(a,b)=>a.size===b.size&&[...a].every(([k,v])=>b.get(k)===v);
const truth=(p,b)=>[...p].reduce((a,[m,c])=>a+(((m&b)===m)?c:0),0);
const source=R29.map(fail),Q=source.map(()=>P1()); Q[4]=not(V(2));Q[5]=not(V(3));
assert(equal(add(...source.map((f,j)=>mul(Q[j],f))),P1()),'R29 fixed F identity');
for(let x=0;x<16;x++)assert(source.some(f=>truth(f,BigInt(x))!==0),'F unsatisfiable');
const result=[];
for(let k of [3,4,5]){
 const offs=4*k, us=Array.from({length:k+1},(_,i)=>offs+i),ts=Array.from({length:k},(_,i)=>offs+k+1+i),aux=offs+2*k+1;
 const cols=[];const a=[];
 function addTerm(f,m){assert([...m.keys()].every(mask=>mask.toString(2).replace(/0/g,'').length<=3),'degree <=3');cols.push(f);a.push(m)}
 addTerm(V(us[0]),P1());addTerm(not(V(us[k])),P1());
 for(let i=1;i<=k;i++){
  const A=V(us[i-1]),B=V(us[i]),T=V(ts[i-1]);
  const f1=mul(A,not(B)),f2=mul(T,not(B)),f3=mul(T,A),f4=mul(B,mul(not(A),not(T)));
  assert(equal(sub(add(f1,f2,mul(B,f3)),f4),add(T,sc(B,-1),A)),'local selector identity');
  for(const [f,m] of [[f1,sc(P1(),-1)],[f2,sc(P1(),-1)],[f3,sc(B,-1)],[f4,P1()]])addTerm(f,m);
 }
 for(let i=0;i<k;i++)for(let j=0;j<source.length;j++){
  const cl=R29[j].map(([v,b])=>[v+4*i,b]);
  const x=fail([cl[0]]),y=fail([cl[1]]),z=fail([cl[2]]),T=V(ts[i]),A=V(aux+9*i+j);
  const g1=mul(T,mul(x,not(A))),g2=mul(A,mul(y,z));
  assert(equal(add(mul(mul(y,z),g1),mul(mul(T,x),g2)),mul(T,fail(cl))),'actual OR gadget');
  let Q=P1();if(j===4)Q=not(V(4*i+2));if(j===5)Q=not(V(4*i+3));
  addTerm(g1,mul(Q,mul(y,z)));addTerm(g2,mul(Q,mul(T,x)));
 }
 assert(equal(add(...cols.map((f,i)=>mul(f,a[i]))),P1()),'onehot certified FALSE polynomial identity');
 let count=0;
 for(let raw=0;raw<2**(2*k+1);raw++){
  let bits=0n;[...us,...ts].forEach((v,j)=>{if(raw & (1<<j))bits|=1n<<BigInt(v)});
  const isValid=cols.slice(0,4*k+2).every(c=>truth(c,bits)===0);
  if(isValid){count++;const tt=ts.map(v=>(bits&(1n<<BigInt(v)))!==0n);assert(tt.filter(Boolean).length===1,'unique selected branch');}
 }
 assert(count===k,'exactly k selected states');
 result.push({k,clause_count:cols.length,valid_states:count});
}
console.log(JSON.stringify({run:'R30-ONEHOT-INDEPENDENT-JS',pass:true,assertions:tests,cases:result},null,2));
