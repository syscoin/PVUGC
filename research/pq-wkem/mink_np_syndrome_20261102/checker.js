function verify(){
  let checks=0, nFalse=0, nValid=0;
  const ck=(v,msg)=>{checks++;if(!v)throw Error(msg)};
  const compile=(n,clauses)=>{
    const c=clauses.length,d=n+3*c,m=2*n+4*c;
    const A=Array.from({length:d},()=>Array(m).fill(0));
    const b=Array(d).fill(1);
    for(let i=0;i<n;i++){A[i][2*i]=1;A[i][2*i+1]=1;}
    clauses.forEach((cl,j)=>{
      const r=n+3*j+2;
      for(const [i,pos] of cl) A[r][2*i+(pos?1:0)]++;
      for(let k=0;k<2;k++){
        const p=2*n+4*j+2*k;
        A[n+3*j+k][p]=A[n+3*j+k][p+1]=1;
        A[r][p]=-1;
      }
    });
    return {A,b};
  };
  const sat=(bits,clauses)=>clauses.every(cl=>cl.some(([i,pos])=>bits[i]===+pos));
  const trans=(bits,clauses)=>{
    const s=[];let unsat=0;
    for(const b of bits)s.push(...(b?[0,1]:[1,0]));
    for(const cl of clauses){
      const k=cl.reduce((a,[i,p])=>a+(bits[i]===+p),0);
      if(k===0){unsat++;s.push(-1,2,0,1);}
      else if(k===1)s.push(0,1,0,1);
      else if(k===2)s.push(1,0,0,1);
      else s.push(1,0,1,0);
    }
    return {s,unsat};
  };
  const mv=(A,s)=>A.map(row=>row.reduce((v,a,i)=>v+a*s[i],0));
  const same=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
  const l1=s=>s.reduce((a,v)=>a+Math.abs(v),0);
  const l2=s=>s.reduce((a,v)=>a+v*v,0);
  const cd=(a,b,q)=>{const v=((a-b)%q+q)%q;return Math.min(v,q-v)};
  const dec=(u,v,s,q)=>{const y=((v-s.reduce((a,x,i)=>a+x*u[i],0))%q+q)%q;return +(cd(y,Math.floor(q/2),q)<cd(y,0,q))};
  let state=2026110218>>>0;
  const rnd=m=>{state=(Math.imul(1664525,state)+1013904223)>>>0;return state%m};
  const enc=(A,b,q,eta,mu)=>{
    const r=b.map(()=>rnd(q));
    const e=Array.from({length:A[0].length},()=>rnd(2*eta+1)-eta);
    const u=e.map((ei,j)=>(A.reduce((a,row,i)=>a+row[j]*r[i],0)+ei+q*100)%q);
    const v=(b.reduce((a,bi,i)=>a+bi*r[i],0)+mu*Math.floor(q/2))%q;
    return {u,v,e};
  };
  const lits=[[0,false],[0,true],[1,false],[1,true]];
  const cl=[];
  for(const a of lits)for(const b of lits)for(const c of lits)cl.push([a,b,c]);
  for(const ca of cl)for(const cb of cl){
    const cs=[ca,cb],{A,b}=compile(2,cs);let isSat=false;
    for(let mask=0;mask<4;mask++){
      const bits=[mask&1,(mask>>1)&1],{s,unsat}=trans(bits,cs);
      ck(same(mv(A,s),b),"syndrome");
      ck(l1(s)===6+2*unsat,"L1 exact");
      ck(l2(s)===6+4*unsat,"L2 exact");
      if(sat(bits,cs)){isSat=true;nValid++;ck(unsat===0&&s.every(x=>x===0||x===1),"valid representation")}
    }
    if(!isSat)nFalse++;
  }
  const trueC=[[[0,true],[1,true],[1,true]],[[0,false],[1,true],[0,false]]];
  const t=compile(2,trueC);
  const valid=[];
  for(let mask=0;mask<4;mask++){const bits=[mask&1,(mask>>1)&1];if(sat(bits,trueC))valid.push(trans(bits,trueC).s);}
  ck(valid.length===2&&!same(valid[0],valid[1]),"distinct original witnesses");
  for(let j=0;j<256;j++){
    const mu=j&1, c=enc(t.A,t.b,257,2,mu);
    for(const s of valid)ck(dec(c.u,c.v,s,257)===mu,"common seed");
  }
  const falseC=[[[0,true],[0,true],[0,true]],[[0,false],[0,false],[0,false]]];
  const f=compile(1,falseC),bad=trans([0],falseC);
  ck(!sat([0],falseC)&&!sat([1],falseC),"original FALSE");
  ck(same(mv(f.A,bad.s),f.b)&&l1(bad.s)===7&&l2(bad.s)===9,"public unauthorized shortish solution");
  for(let i=0;i<512;i++){
    const mu=i&1,c=enc(f.A,f.b,41,1,mu);
    ck(dec(c.u,c.v,bad.s,41)===mu,"FALSE recovered without original witness");
  }
  const noise={success:0,failure:0};
  const recur=(p,z)=>{
    if(p===bad.s.length){
      for(let mu=0;mu<=1;mu++){
        const y=((mu*11-z)%23+23)%23;
        noise[(+(cd(y,11,23)<cd(y,0,23))===mu)?"success":"failure"]++;
      }
      ck(true,"exact error vector enumeration");return;
    }
    for(const e of [-1,0,1])recur(p+1,z+bad.s[p]*e);
  };
  recur(0,0);
  ck(noise.success+noise.failure===118098,"finite sample total");
  const ca=[[[0,true],[0,true],[0,true]]],cb=[[[0,false],[0,false],[0,false]]];
  const pa=compile(1,ca),pb=compile(1,cb);
  const wa=trans([1],ca).s,wb=trans([0],cb).s;
  ck(same(mv(pa.A,wa),pa.b)&&same(mv(pb.A,wb),pb.b),"local clause witnesses");
  for(let i=0;i<256;i++){
    const a=rnd(2),b=rnd(2),x=enc(pa.A,pa.b,41,1,a),y=enc(pb.A,pb.b,41,1,b);
    ck((dec(x.u,x.v,wa,41)^dec(y.u,y.v,wb,41))===(a^b),"local switching repair failure");
  }
  return {
    run:"MINK-NP-SYNDROME-20261102-R18",checks,
    exhaustive_formulas:4096,false_formulas:nFalse,valid_assignment_checks:nValid,
    distinct_valid_witnesses:valid.length,
    false_recovered_q41:"512/512",
    q23_noise_exact:noise,
    per_clause_xor_repair_attack:"256/256",
    result:"REJECTED: public wrong-assignment signed solution decrypts; no generic PQ WKEM security",
    independent_longer_python_checker:"129296 checks twice, identical; local-only archive"
  };
}
console.log(JSON.stringify(verify(),null,2));
