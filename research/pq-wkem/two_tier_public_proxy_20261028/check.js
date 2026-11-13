const verify = function verify(){
  const q=65537,h=800,g=2*h+1,radix=Math.floor(q/g),m=2000,t=3,ell=49;
  let checks=0; function ck(b,s){if(!b)throw Error(s);checks++;}
  const clauses=[
    [[2,1],[3,0],[5,0]],[[2,0],[3,0],[5,0]],[[0,1],[1,1],[3,1]],
    [[1,0],[3,0],[5,1]],[[1,1],[3,0],[5,1]],[[0,0],[2,1],[3,1]],
    [[1,1],[2,0],[3,1]],[[1,0],[2,0],[3,1]],[[0,1],[1,0],[4,1]],
    [[3,1],[4,0],[5,1]],[[0,1],[1,0],[5,0]]
  ];
  const masks=Array.from({length:64},(_,i)=>i).filter(i=>i.toString(2).replace(/0/g,"").length<=3 && i!==0);
  ck(masks.length===41,"degree-three nonconstant monomials");
  for(let w=0;w<64;w++)ck(clauses.some(C=>!C.some(([i,p])=>((w>>i)&1)===p)),"FALSE original 3CNF");
  function poly(C){
    let P=new Map([[0,1]]);
    for(const [i,positive] of C){
      const T=positive?[[0,1],[1<<i,-1]]:[[1<<i,1]];
      const N=new Map();
      for(const [u,v] of P)for(const [z,k] of T)N.set(u|z,(N.get(u|z)||0)+v*k);
      P=new Map([...N].filter(([,v])=>v!==0));
    }
    return P;
  }
  const E=clauses.map(C=>{const P=poly(C);return {a:masks.map(z=>P.get(z)||0),b:-(P.get(0)||0)};});
  const z=masks.map(mask=>mask===5?1:mask===9?-1:0);
  ck(z.some(v=>v!==0) && z.every((v,i)=>masks[i].toString(2).replace(/0/g,"").length!==1||v===0),"non-ORIGINAL pseudo moment");
  for(const row of E)ck(row.a.reduce((v,a,i)=>v+a*z[i],0)===row.b,"exact E cancellation");
  const L=[];
  for(let i=0;i<6;i++){const a=masks.map(x=>x===(1<<i)?1:0);L.push({a,b:0},{a,b:1});}
  for(const C of clauses){
    const a=masks.map(mask=>C.reduce((v,[i,p])=>v+(mask===(1<<i)?(p?1:-1):0),0));
    L.push({a,b:2-C.filter(([,p])=>!p).length});
  }
  ck(L.length===23,"low row count");
  const residual=L.map(row=>row.b-row.a.reduce((s,x,j)=>s+x*z[j],0));
  ck(residual.every(v=>Math.abs(v)<=2)&&residual.some(v=>Math.abs(v)===2),"invalid but bounded proxy residual");
  let seed=20261028>>>0; function rnd(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
  function field(){return rnd()%q;}
  function key(){let k=0n;for(let i=0;i<8;i++)k=(k<<32n)|BigInt(rnd());return k;}
  function maskCounts(){
    const indices=Array.from({length:m},(_,i)=>i),counts=Array(L.length).fill(0);
    for(let i=0;i<h;i++){
      const j=i+(rnd()%(m-i));[indices[i],indices[j]]=[indices[j],indices[i]];
      counts[indices[i]%L.length]+=rnd()&1?1:-1;
    }
    return counts;
  }
  function cyc(v){return (v%q+q)%q;}
  function distance(a,b){let d=cyc(a-b);return Math.min(d,q-d);}
  const fullTrials=3;
  for(let trial=0;trial<fullTrials;trial++){
    const K=key(),U=key(),shares=Array.from({length:t},key);
    const D=shares.reduce((v,s)=>v^s,U),V=K^U;
    const reconstructed=[];
    for(const share of shares){
      let v=share,got=0n,mult=1n;
      for(let j=0;j<ell;j++){
        const a=Number(v%BigInt(radix));v/=BigInt(radix);
        const u=E.map(field),counts=maskCounts();
        const c=masks.map((_,k)=>cyc(E.reduce((s,row,i)=>s+u[i]*row.a[k],0)+L.reduce((s,row,i)=>s+counts[i]*row.a[k],0)));
        const d=cyc(E.reduce((s,row,i)=>s+u[i]*row.b,0)+L.reduce((s,row,i)=>s+counts[i]*row.b,0)+g*a);
        const revealed=cyc(d-c.reduce((s,x,k)=>s+x*z[k],0));
        const possible=Array.from({length:radix},(_,i)=>i).filter(x=>distance(revealed,g*x)<=h);
        ck(possible.length===1 && possible[0]===a,"public invalid proxy decrypts full c/d");
        got+=BigInt(possible[0])*mult; mult*=BigInt(radix);
      }
      ck(v===0n && got===share,"full 256-bit share recovered");
      reconstructed.push(got);
    }
    ck((reconstructed.reduce((v,s)=>v^s,D)^V)===K,"full FALSE instance precommitted capability recovered");
  }
  const log2Failure=Math.log2(2*t*ell)-h/(8*Math.log(2));
  ck(log2Failure< -128,"high-probability classical attack");
  return {status:"NO_POSITIVE_SECURE_ADVANCE",verified_checks:checks,original_false_assignments:64,monomial_columns:masks.length,exact_rows:E.length,low_row_types:L.length,public_proxy_support:[["x0*x2",1],["x0*x3",-1]],q,h,g,radix,capsules:t,columns:t*ell,full_256bit_false_key_recoveries:fullTrials,log2_upper_bound_attack_failure:Number(log2Failure.toFixed(6)),security:"arbitrary-FALSE complete-public SOURCE fails, no original witness needed"};
};
console.log(JSON.stringify(verify(),null,2));
