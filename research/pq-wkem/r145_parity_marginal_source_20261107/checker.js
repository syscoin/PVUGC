function checker() {
  let checks=0;
  function ok(b,label){checks++;if(!b)throw Error("R145 failed "+label);}
  function pop(x){let a=0;while(x){a+=x&1;x>>>=1;}return a;}
  for(let n=3;n<=10;n++){
    const N=1<<n, full=N-1;
    const even=[],odd=[];
    for(let x=0;x<N;x++)(pop(x)%2?odd:even).push(x);
    ok(even.length===odd.length&&even.length===N/2,"parity classes");
    for(let mask=0;mask<full;mask++){
      const a=even.filter(x=>(x&mask)===mask).length;
      const b=odd.filter(x=>(x&mask)===mask).length;
      ok(a===b && a===2**(n-1-pop(mask)),"proper moment");
    }
    ok(even.filter(x=>(x&full)===full).length!==odd.filter(x=>(x&full)===full).length,"degree n distinguishes");
  }
  const n=3, all=Array.from({length:8},(_,i)=>i);
  const even=all.filter(x=>pop(x)%2===0),odd=all.filter(x=>pop(x)%2===1);
  const labels=[...even,...odd];
  const H=[labels.map((_,j)=>j<4?1:0),labels.map((_,j)=>j>=4?1:0)];
  const b=[1,1];
  for(let mask=1;mask<8;mask++)if(pop(mask)<=2){
    H.push(labels.map((x,j)=>(j<4?1:-1)*Number((x&mask)===mask)));b.push(0);
  }
  ok(H.length===8&&H.every(row=>row.length===8),"matrix shape");
  const Z=Array(8).fill(1);
  for(let i=0;i<8;i++)ok(H[i].reduce((a,v,j)=>a+v*Z[j],0)===4*b[i],"fractional pseudocert");
  for(let x=0;x<8;x++){
    const clauses=[...odd,...even];
    ok(!clauses.every(forbidden=>x!==forbidden),"original false CNF");
  }
  let seed=0x14520267;
  function next(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;}
  const q=4093,Delta=101,N=4096;
  function mod(x){return ((x%q)+q)%q;}
  function circ(a,b){const d=mod(a-b);return Math.min(d,q-d);}
  for(let t=0;t<N;t++){
    const s=Array.from({length:8},()=>next()%q);
    const e=Array.from({length:8},()=>(next()%3)-1);
    const eta=(next()%3)-1,K=next()%2;
    const c=Array.from({length:8},(_,j)=>mod(H.reduce((sum,row,i)=>sum+row[j]*s[i],0)+e[j]));
    const p=mod(b.reduce((sum,v,i)=>sum+v*s[i],0)+Delta*K+eta);
    const phase=mod(4*p-c.reduce((sum,v,j)=>sum+Z[j]*v,0));
    const direct=mod(4*Delta*K+4*eta-e.reduce((sum,v)=>sum+v,0));
    ok(phase===direct,"identity");
    const guess=circ(phase,0)<circ(phase,4*Delta)?0:1;
    ok(guess===K,"false source recovers capability");
  }
  return {run:"R145-parity-moment-lift",checks,clauses:8,dimension:8,odd_modulus:q,delta:Delta,public_counterfeit_denominator:4,samples:N,all_recovered:N,degree_tested:"3..10",scope:"FALSE source counterexample only; no QPT-LWE claim"};
}

const captured = checker();
console.log(JSON.stringify(captured, null, 2));
