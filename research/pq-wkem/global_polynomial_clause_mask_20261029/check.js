function runChecker(){
  const q=257; let checks=0;
  function ok(condition,label){checks++;if(!condition)throw Error("FAILED "+label);}
  function mod(x){return ((x%q)+q)%q;}
  function mul(a,b){
    const z={};
    for(const [ka,va] of Object.entries(a))for(const [kb,vb] of Object.entries(b)){
      const m=(+ka)|(+kb);z[m]=mod((z[m]||0)+va*vb);
    }
    return z;
  }
  function violate(clause){
    let p={0:1};
    for(const [i,pos] of clause) p=mul(p,pos?{0:1,[1<<i]:q-1}:{[1<<i]:1});
    return p;
  }
  function basis(n){
    const a=[];
    for(let d=0;d<=Math.min(3,n);d++){
      function rec(last,remain,mask){
        if(!remain){a.push(mask);return;}
        for(let i=last;i<=n-remain;i++)rec(i+1,remain-1,mask|(1<<i));
      }
      rec(0,d,0);
    }
    return a;
  }
  function inverse(a){
    for(let k=1;k<q;k++)if(mod(a*k)===1)return k;
    throw Error("noninvertible");
  }
  function linearFunctional(clauses,n){
    const b=basis(n), pol=clauses.map(violate), D=b.length, rhs=[...pol.map(()=>0),1];
    const aug=[...pol,{0:1}].map((p,i)=>[...b.map(mask=>p[mask]||0),rhs[i]]);
    const piv=[];let rank=0;
    for(let col=0;col<D&&rank<aug.length;col++){
      let r=rank;while(r<aug.length&&!aug[r][col])r++;
      if(r===aug.length)continue;
      [aug[rank],aug[r]]=[aug[r],aug[rank]];
      let scale=inverse(aug[rank][col]);
      for(let j=col;j<=D;j++)aug[rank][j]=mod(aug[rank][j]*scale);
      for(let i=0;i<aug.length;i++){
        if(i!==rank&&aug[i][col]){
          const f=aug[i][col];
          for(let j=col;j<=D;j++)aug[i][j]=mod(aug[i][j]-f*aug[rank][j]);
        }
      }
      piv.push(col);rank++;
    }
    if(aug.some(row=>row.slice(0,D).every(v=>v===0)&&row[D]!==0))return {lambda:null,b,pol};
    const lambda=Array(D).fill(0);
    for(let i=0;i<piv.length;i++)lambda[piv[i]]=aug[i][D];
    ok(lambda[0]===1,"unit functional");
    for(const p of pol)ok(mod(b.reduce((s,m,i)=>s+lambda[i]*(p[m]||0),0))===0,"constraint annihilation");
    return {lambda,b,pol};
  }
  function evaluate(p,x){return mod(Object.entries(p).reduce((s,[mask,v])=>s+(((x&(+mask))===(+mask))?v:0),0));}
  function isSat(c,x){return c.some(([i,pos])=>Boolean(x&(1<<i))===pos);}
  function digitVector(a,pol,b,rand){
    const p={0:a};
    for(const v of pol){const r=rand();for(const [mask,val] of Object.entries(v))p[mask]=mod((p[mask]||0)+r*val);}
    return b.map(m=>p[m]||0);
  }
  function dot(a,b){return mod(a.reduce((s,x,i)=>s+x*b[i],0));}
  let seed=20261029;
  function rnd(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%q;}
  function randByte(){return rnd()%256;}
  function xor(list){return Array.from({length:32},(_,i)=>list.reduce((a,v)=>a^v[i],0));}
  const K=Array.from({length:32},randByte),U0=Array.from({length:32},randByte);
  const shares=Array.from({length:3},()=>Array.from({length:32},randByte));
  const D=xor([U0,...shares]), V=xor([K,U0]);
  function fullBreak(clauses,n){
    const {lambda,b,pol}=linearFunctional(clauses,n);
    ok(lambda!==null,"public coefficient extractor exists");
    const opened=shares.map(sh=>sh.map(a=>dot(lambda,digitVector(a,pol,b,rnd))));
    for(let i=0;i<3;i++)for(let j=0;j<32;j++)ok(opened[i][j]===shares[i][j],"extracted byte");
    const recovered=xor([V,D,...opened]);
    ok(recovered.every((v,i)=>v===K[i]),"full capability recovered");
    return {lambda,b,pol};
  }
  const valid=[
    [[0,true],[1,true],[2,true]],
    [[2,true],[3,true],[4,true]]
  ];
  const t=fullBreak(valid,5);
  let trueWitnesses=0;
  for(let x=0;x<32;x++){
    if(valid.every(c=>isSat(c,x))){
      trueWitnesses++;
      for(const p of t.pol)ok(evaluate(p,x)===0,"valid witness mask zero");
    }
  }
  ok(trueWitnesses===25,"multiple ORIGINAL witnesses");
  const impossible=[
    [[0,false],[0,false],[0,false]],
    [[0,true],[0,true],[1,false]],
    [[1,true],[1,true],[1,true]]
  ];
  let falseAssignments=0;
  for(let x=0;x<4;x++){ok(!impossible.every(c=>isSat(c,x)),"fixed FALSE statement");falseAssignments++;}
  const f=fullBreak(impossible,2);
  ok(f.b.every((mask,i)=>mask===i),"false polynomial basis order");
  ok(f.lambda.join(",")==="1,0,1,1","explicit false-instance extractor");
  const trivial=[[[0,true],[0,true],[0,true]],[[0,false],[0,false],[0,false]]];
  ok(linearFunctional(trivial,1).lambda===null,"not every false has an extractor");
  return {status:"CANDIDATE_BROKEN",q,assertions:checks,distinct_valid_original_witnesses:trueWitnesses,false_assignments_checked:falseAssignments,shares:3,seed_bytes:32,public_false_extractor:f.lambda,full_key_recovered_without_any_witness:true};
}
console.log(JSON.stringify(runChecker(),null,2));
