'use strict';
const assert = require('node:assert/strict');
let assertions=0, fixtures=0, fullStates=0;
function check(cnf,n,full=false){
 const input=Array.from({length:n},(_,i)=>['v',i]);
 function lit(l){const v=input[Math.abs(l)-1];return l>0?v:['n',v]}
 function fold(xs,op){return xs.slice(1).reduce((a,b)=>[op,a,b],xs[0])}
 const root=fold(cnf.map(c=>fold(c.map(lit),'o')),'a');
 const evalExpr=(e,w)=>e[0]==='v'?w[e[1]]:e[0]==='n'?1-evalExpr(e[1],w):e[0]==='a'?(evalExpr(e[1],w)&evalExpr(e[2],w)):(evalExpr(e[1],w)|evalExpr(e[2],w));
 let at=n; const f=[]; const emit=(...g)=>{assert.equal(new Set(g.slice(1)).size,g.length-1);f.push(g)};
 function gen(e){if(e[0]==='v')return e[1];const a=gen(e[1]),b=e[0]==='n'?null:gen(e[2]),t=at++;
 if(e[0]==='n'){emit('X',t);emit('C',a,t)}
 else if(a===b)emit('C',a,t);
 else if(e[0]==='a')emit('T',a,b,t);
 else{emit('C',a,t);emit('C',b,t);emit('T',a,b,t)}return t}
 const o=gen(root), flag=at, tape=[...f,['C',o,flag],...f.slice().reverse()];
 function execute(s,seq=tape){for(const g of seq){if(g[0]==='X')s^=1<<g[1];if(g[0]==='C'&&(s>>g[1]&1))s^=1<<g[2];if(g[0]==='T'&&(s>>g[1]&1)&&(s>>g[2]&1))s^=1<<g[3]}return s}
 let bad=0;
 for(let mask=0;mask<1<<n;mask++){const w=Array.from({length:n},(_,i)=>mask>>i&1),v=evalExpr(root,w);bad+=v;
 for(let b=0;b<2;b++){const s=mask|(b<<flag);assert.equal(execute(s)^s,v<<flag);assertions++}}
 if(full){const seen=new Set();for(let s=0;s<1<<(flag+1);s++){const v=execute(s);assert(!seen.has(v));seen.add(v);assert.equal(execute(v,tape.slice().reverse()),s);assertions+=2;fullStates++}}
 fixtures++;return bad
}
assert.equal(check([[1],[-1]],2,true),0);assertions++;
assert.equal(check([[1,-1]],2,true),4);assertions++;
assert.equal(check([[1],[-2],[3],[4]],4),1);assertions++;
const cls=[[1],[-1],[2],[-2],[1,2],[-1,-2],[1,-2],[-1,2]];
for(let i=0;i<cls.length;i++)for(let j=i;j<cls.length;j++)check([cls[i],cls[j]],2);
console.log(JSON.stringify({run:453,fixtures,assertions,fullStates,model:'reversible clean-ancilla weak equivalence',result:'totality iff CNF unsat',security:'NOT PQ WKEM'}));
