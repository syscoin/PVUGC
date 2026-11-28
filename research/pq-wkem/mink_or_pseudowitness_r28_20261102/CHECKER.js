function checker(){
  const F=[
    [[3,0],[1,1],[2,0]],[[0,1],[3,1],[2,1]],[[2,1],[0,1],[3,0]],
    [[3,1],[2,0],[1,0]],[[1,1],[0,0],[3,1]],[[1,0],[2,1],[0,0]],
    [[2,0],[3,0],[1,0]],[[1,1],[2,0],[3,1]],[[2,1],[3,0],[0,0]]
  ],G=[[[0,1],[1,1],[2,1]],[[0,0],[1,1],[2,1]],[[1,0],[2,1],[0,1]]];
  const t=4,ybase=5,abase=8,bbase=17,n=20,q=65537,Delta=32768;
  let checks=0,seed=2026110228;
  const ck=(b,s)=>{checks++;if(!b)throw Error(s)};
  const rnd=(M)=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%M};
  const mod=x=>((x%q)+q)%q;
  const add=(a,b)=>{const c={...a};for(const [k,v] of Object.entries(b))c[k]=(c[k]||0)+v;return Object.fromEntries(Object.entries(c).filter(([k,v])=>v!==0))};
  const neg=a=>Object.fromEntries(Object.entries(a).map(([k,v])=>[k,-v]));
  const mul=(a,b)=>{const c={};for(const [k,v] of Object.entries(a))for(const [l,w] of Object.entries(b)){const u=(+k)|(+l);c[u]=(c[u]||0)+v*w}return Object.fromEntries(Object.entries(c).filter(([k,v])=>v!==0))};
  const OR=(a,b)=>add(add(a,b),neg(mul(a,b)));
  const ONE={"0":1},ZERO={};
  const lit=(v,p)=>p?{[1<<v]:1}:add(ONE,neg({[1<<v]:1}));
  const clauses=[];
  for(let i=0;i<F.length;i++){const [a,b,c]=F[i];clauses.push([[t,1],a,[abase+i,1]],[[abase+i,0],b,c])}
  for(let i=0;i<G.length;i++){const [a,b,c]=G[i].map(([v,p])=>[v+ybase,p]);clauses.push([[t,0],a,[bbase+i,1]],[[bbase+i,0],b,c])}
  const SUB=Array.from({length:n},(_,i)=>i<4?{[1<<i]:1}:{});
  for(let i=0;i<F.length;i++){SUB[abase+i]=OR(lit(...F[i][1]),lit(...F[i][2]))}
  for(let i=0;i<G.length;i++){
    const cp=([v,p])=>p?ZERO:ONE;
    SUB[bbase+i]=OR(cp(G[i][1]),cp(G[i][2]));
  }
  const substitute=m=>{let s=ONE;for(let i=0;i<n;i++)if(m&(1<<i))s=mul(s,SUB[i]);return s};
  const pseudo=p=>(p[0]||0)-(p[(1<<0)|(1<<2)]||0);
  const failure=c=>{let z=ONE;for(const [v,p] of c)z=mul(z,p?add(ONE,neg({[1<<v]:1})):{[1<<v]:1});return z};
  const B=clauses.map(failure);
  const rows=[...new Set([0,...B.flatMap(b=>Object.keys(b).map(Number))])].sort((a,b)=>a-b);
  const ell=Object.fromEntries(rows.map(m=>[m,pseudo(substitute(m))]));
  const value=p=>Object.entries(p).reduce((s,[m,v])=>s+(ell[m]||0)*v,0);
  ck(ell[0]===1,"normalization");
  for(let j=0;j<B.length;j++){
    ck(value(B[j])===0,"mask annihilation "+j);
    let actual=ZERO;
    for(const [m,v] of Object.entries(B[j]))actual=add(actual,Object.fromEntries(Object.entries(substitute(+m)).map(([u,c])=>[u,c*v])));
    const expected=j<2*F.length?(j%2?ZERO:failure(F[Math.floor(j/2)])):ZERO;
    ck(JSON.stringify(actual)===JSON.stringify(expected),"substitution identity "+j);
  }
  const sat=(c,a)=>c.every(cl=>cl.some(([v,p])=>a[v]===p));
  let gs=0;
  for(let x=0;x<16;x++)ck(!sat(F,Array.from({length:4},(_,i)=>(x>>i)&1)),"F false");
  for(let y=0;y<8;y++)if(sat(G,Array.from({length:3},(_,i)=>(y>>i)&1)))gs++;
  ck(gs===5,"G witnesses");
  for(let x=0;x<16;x++)for(let tv=0;tv<2;tv++)for(let y=0;y<8;y++){
    const X=Array.from({length:4},(_,i)=>(x>>i)&1),Y=Array.from({length:3},(_,i)=>(y>>i)&1);
    const A=[...X,tv,...Y,...F.map(c=>+c.slice(1).some(([v,p])=>X[v]===p)),...G.map(c=>+c.slice(1).some(([v,p])=>Y[v]===p))];
    ck(sat(clauses,A)===(tv===1&&sat(G,Y)),"OR iff");
    if(sat(clauses,A))for(let j=0;j<B.length;j++)ck(Object.entries(B[j]).reduce((z,[m,v])=>z+v*([...Array(n).keys()].every(i=>!(+m&(1<<i))||A[i])?1:0),0)===0,"true annihilation");
  }
  const L1=Object.values(ell).reduce((s,v)=>s+Math.abs(v),0);
  ck(rows.length===74&&L1===9&&Object.values(ell).filter(Boolean).length===9,"sparse pseudo footprint");
  ck(value({0:1,[1<<t]:-1})===1,"bounded implication repairs only this dual");
  const c0=Object.fromEntries(rows.map(m=>[m,0]));
  let leaked=0;
  for(let mu=0;mu<2;mu++)for(let trial=0;trial<256;trial++){
    const e=Object.fromEntries(rows.map(m=>[m,rnd(3)-1]));
    const c={...c0};
    for(const m of rows)c[m]=mod((m===0?Delta*mu:0)+e[m]);
    for(const b of B){const r=rnd(q);for(const [m,v] of Object.entries(b))c[m]=mod(c[m]+r*v)}
    const got=mod(value(c)),noise=value(e);
    ck(got===mod(Delta*mu+noise),"full ciphertext exact");
    const d0=Math.min(got,q-got),dd=mod(got-Delta),d1=Math.min(dd,q-dd);
    ck((d0<d1?0:1)===mu,"no-witness release");leaked++;
  }
  return {id:"MINK-OR-PSEUDOWITNESS-R28-JS",checks,pass:true,q,Delta,eta:1,clauses:clauses.length,variables:n,rows:rows.length,pseudo_l1:L1,nonzero:9,g_witnesses:gs,recovered_without_witness:leaked,limitation:"degree-zero Boolean quotient only; NOT generic NP security or QPT construction"};
}
console.log(JSON.stringify(checker(),null,2));
