(function verify(){
  let checks=0, seed=2026102823>>>0;
  const ok=(v)=>{if(!v)throw Error("assert "+(checks+1));checks++};
  const r32=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0};
  const rint=(n)=>r32()%n, mod=(v,q)=>(v%q+q)%q;
  function compile(v,clauses){
    const c=clauses.length,N=v+2*c, nr=N+c,nc=2*N;
    const rows=Array.from({length:nr},()=>new Map());
    for(let i=0;i<N;i++){rows[i].set(2*i,1);rows[i].set(2*i+1,1)}
    for(let j=0;j<c;j++){
      const row=rows[N+j];
      for(const [i,pos] of clauses[j]){const k=2*i+(pos?1:0);row.set(k,(row.get(k)||0)+1)}
      row.set(2*(v+2*j)+1,1);row.set(2*(v+2*j+1)+1,2);
    }
    return {v,clauses,c,N,nr,nc,rows,U:[...Array(N).fill(1),...Array(c).fill(4)]};
  }
  function opening(o,a,allowFalse){
    let bits=a.slice(),f=0;
    for(const clause of o.clauses){
      const hits=clause.filter(([i,pos])=>Boolean(a[i])===pos).length;
      if(!hits){ok(allowFalse);bits.push(2,1);f++}
      else {const u=4-hits;bits.push(u%2,Math.floor(u/2))}
    }
    const w=bits.flatMap(b=>[1-b,b]);ok(w.length===o.nc);
    return {w,f};
  }
  function Aw(o,w){
    return o.rows.map(row=>{let z=0;for(const [i,c] of row)z+=w[i]*c;return z});
  }
  function encrypt(o,a,q,g){
    const s=Array.from({length:o.nr},()=>rint(q));
    const e=Array.from({length:o.nc},()=>rint(3)-1);
    const c=e.slice();
    for(let i=0;i<o.nr;i++)for(const [j,k] of o.rows[i])c[j]=mod(c[j]+s[i]*k,q);
    const eps=rint(3)-1;
    const d=mod(o.U.reduce((z,x,i)=>z+x*s[i],0)+eps+g*a,q);
    return {c,d};
  }
  function decode(o,ct,w,q,g,T){
    const z=mod(ct.d-w.reduce((t,x,i)=>t+x*ct.c[i],0),q);
    let best=0,dist=q+1;
    for(let a=0;a<T;a++){const v=mod(z-g*a,q),d=Math.min(v,q-v);if(d<dist){dist=d;best=a}}
    return best;
  }
  function random256(){let z=0n;for(let j=0;j<8;j++)z=(z<<32n)|BigInt(r32());return z}
  function digits(x,T,ell){const out=[];for(let i=0;i<ell;i++){out.push(Number(x%BigInt(T)));x/=BigInt(T)}return out}
  function run(o,ws,reps){
    const q=65537,g=2*o.N+3,T=Math.floor(q/g);
    let ell=0,p=1n;while(p<(1n<<256n)){p*=BigInt(T);ell++}
    for(let t=0;t<reps;t++){
      const K=random256(),U0=random256(),sh=[random256(),random256(),random256()];
      const D=U0^sh[0]^sh[1]^sh[2],V=K^U0;
      const capsule=sh.map(z=>digits(z,T,ell).map(a=>encrypt(o,a,q,g)));
      for(const w of ws){
        let recovered=V^D;
        for(const ciphertexts of capsule){
          let z=0n,P=1n;
          for(const ct of ciphertexts){z+=BigInt(decode(o,ct,w,q,g,T))*P;P*=BigInt(T)}
          recovered^=z;
        }
        ok(recovered===K);
      }
    }
    return {trials:reps,ciphertextColumns:3*ell,T,openedWitnesses:ws.length};
  }
  const sat=compile(2,[[[0,true],[1,true],[1,true]],[[0,false],[1,true],[1,true]]]);
  const W0=opening(sat,[0,1],false),W1=opening(sat,[1,1],false);
  ok(W0.f===0&&W1.f===0&&W0.w.join(",")!==W1.w.join(","));
  for(const W of [W0,W1]){ok(Aw(sat,W.w).every((x,i)=>x===sat.U[i]));ok(W.w.reduce((z,x)=>z+Math.abs(x),0)===sat.N)}
  const trueResult=run(sat,[W0.w,W1.w],3);
  const contradiction=v=>compile(v,[...Array(v)].flatMap((_,i)=>[[[i,true],[i,true],[i,true]],[[i,false],[i,false],[i,false]]]));
  const toy=contradiction(4);
  for(let mask=0;mask<16;mask++){const a=Array.from({length:4},(_,i)=>(mask>>i)&1);ok(toy.clauses.some(cl=>!cl.some(([i,p])=>Boolean(a[i])===p)))}
  const unsat=contradiction(32),P=opening(unsat,Array(32).fill(0),true);
  ok(unsat.N===160&&unsat.nr===224&&unsat.nc===320&&P.f===32);
  ok(Aw(unsat,P.w).every((x,i)=>x===unsat.U[i]));
  const l1=P.w.reduce((z,x)=>z+Math.abs(x),0);
  const l2=P.w.reduce((z,x)=>z+x*x,0);
  ok(l1===224&&l2===288&&l1>unsat.N);
  const falseResult=run(unsat,[P.w],5);
  const g=2*unsat.N+3,failLog2=1+Math.log2(falseResult.ciphertextColumns)-(g/2)**2/(2*(1+l2)*Math.LN2);
  ok(failLog2< -50);
  return {status:"NO_SECURE_ADVANCE",checks,trueResult,falseResult,falseInstance:{v:32,c:64,N:unsat.N,pseudoL1:l1,acceptedL1:unsat.N,pseudoL2Squared:l2,attackFailureLog2Upper:Number(failLog2.toFixed(6))},quantum:false,native:"mock capability only"};
})();
