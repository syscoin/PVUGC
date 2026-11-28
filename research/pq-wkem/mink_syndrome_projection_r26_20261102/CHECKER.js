function runR26Main() {
  const q=257;let checks=0,seed=2026110226;
  const ck=(x,s)=>{checks++;if(!x)throw Error("R26 main: "+s);};
  const md=x=>((x%q)+q)%q;
  const rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
  const inv=x=>{let a=md(x),r=1,k=q-2;while(k){if(k&1)r=md(r*a);a=md(a*a);k>>=1;}return r;};
  function mult(a,b){
    const c=new Map();
    for(const [u,x] of a)for(const [v,y] of b){
      const w=u|v;c.set(w,md((c.get(w)||0)+x*y));
    }
    return new Map([...c].filter(x=>x[1]!==0));
  }
  function g(cl){
    let p=new Map([[0,1]]);
    for(const [i,pos] of cl)
      p=mult(p,pos?new Map([[0,1],[1<<i,q-1]]):new Map([[1<<i,1]]));
    return p;
  }
  function fixture(n,c){
    const clauses=[];
    for(let j=0;j<c;j++){
      const vs=new Set();while(vs.size<3)vs.add(rnd()%n);
      const vars=[...vs],pos=vars.map(()=>rnd()&1);
      if(pos.every(x=>x))pos[0]=0;
      clauses.push(vars.map((v,i)=>[v,pos[i]]));
    }
    const columns=[];
    for(const cl of clauses){
      const f=g(cl);columns.push(f);
      for(let i=0;i<n;i++)columns.push(mult(f,new Map([[1<<i,1]])));
    }
    const support=new Set([0]);
    for(const col of columns)for(const u of col.keys())support.add(u);
    const rows=[...support].sort((a,b)=>a-b);
    const B=rows.map(u=>columns.map(col=>col.get(u)||0));
    return {n,c,clauses,rows,B,L:columns.length};
  }
  function echelon(B,track){
    const m=B.length,L=B[0].length;
    const A=B.map(x=>x.slice());
    const T=track?Array.from({length:m},(_,i)=>Array.from({length:m},(_,j)=>+(i===j))):null;
    let rank=0;
    for(let j=0;j<L&&rank<m;j++){
      let p=rank;while(p<m&&!A[p][j])p++;
      if(p===m)continue;
      [A[p],A[rank]]=[A[rank],A[p]];
      if(T)[T[p],T[rank]]=[T[rank],T[p]];
      const d=inv(A[rank][j]);
      for(let k=j;k<L;k++)A[rank][k]=md(A[rank][k]*d);
      if(T)for(let k=0;k<m;k++)T[rank][k]=md(T[rank][k]*d);
      for(let i=rank+1;i<m;i++)if(A[i][j]){
        const s=A[i][j];
        for(let k=j;k<L;k++)A[i][k]=md(A[i][k]-s*A[rank][k]);
        if(T)for(let k=0;k<m;k++)T[i][k]=md(T[i][k]-s*T[rank][k]);
      }
      rank++;
    }
    if(T)for(let i=rank;i<m;i++)for(let j=0;j<L;j++)ck(A[i][j]===0,"left-nullspace");
    return {rank,H:T?T.slice(rank):null};
  }
  function coordinate(H,v) {
    const n=v.length,k=H.length;
    if(!k){ck(v.every(x=>x===0),"zero coordinate");return [];}
    const A=Array.from({length:n},(_,i)=>H.map(h=>h[i]).concat(v[i]));
    let row=0;
    for(let col=0;col<k;col++){
      let pivot=row;while(pivot<n&&!A[pivot][col])pivot++;
      ck(pivot<n,"H full rank");
      [A[row],A[pivot]]=[A[pivot],A[row]];
      const d=inv(A[row][col]);
      for(let j=col;j<=k;j++)A[row][j]=md(A[row][j]*d);
      for(let i=0;i<n;i++)if(i!==row&&A[i][col]){
        const f=A[i][col];
        for(let j=col;j<=k;j++)A[i][j]=md(A[i][j]-f*A[row][j]);
      }
      row++;
    }
    for(let i=k;i<n;i++)ck(A[i][k]===0,"valid lambda belongs to rowspace");
    const omega=A.slice(0,k).map(x=>x[k]);
    for(let i=0;i<n;i++){
      let y=0;for(let j=0;j<k;j++)y+=omega[j]*H[j][i];
      ck(md(y)===v[i],"coordinate reconstruction");
    }
    return omega;
  }
  const reports=[];
  for(const [n,c] of [[8,12],[10,20]]){
    const f=fixture(n,c),{rank,H}=echelon(f.B,n===8);
    ck(rank>0&&rank<f.rows.length,"nontrivial projection");
    const report={variables:n,clauses:c,original_rows:f.rows.length,mask_columns:f.L,rank,syndrome_rows:f.rows.length-rank};
    if(n===8){
      let valid=0;
      for(let a=0;a<(1<<n);a++){
        const sat=f.clauses.every(cl=>cl.some(([i,p])=>((a>>i)&1)===p));
        if(!sat)continue;
        valid++;
        const lambda=f.rows.map(mask=>+((mask&a)===mask));
        for(let j=0;j<f.L;j++){
          let x=0;for(let i=0;i<f.rows.length;i++)x+=lambda[i]*f.B[i][j];
          ck(md(x)===0,"ORIGINAL witness annihilates B");
        }
        const omega=coordinate(H,lambda);
        const r=Array.from({length:f.L},()=>rnd()%q);
        const e=f.rows.map(()=>rnd()%3-1);
        const mu=rnd()%2,delta=120;
        const C=f.rows.map((mask,i)=>{
          let x=e[i]+(mask===0?delta*mu:0);
          for(let j=0;j<f.L;j++)x+=f.B[i][j]*r[j];
          return md(x);
        });
        const s=H.map(h=>md(h.reduce((z,x,i)=>z+x*C[i],0)));
        const direct=md(lambda.reduce((z,x,i)=>z+x*C[i],0));
        const compact=md(omega.reduce((z,x,i)=>z+x*s[i],0));
        ck(direct===compact,"raw SAME-capability extraction");
        ck(direct===md(delta*mu+lambda.reduce((z,x,i)=>z+x*e[i],0)),"correct noise identity");
        for(let j=0;j<3;j++){
          const u=Array.from({length:f.L},()=>rnd()%q);
          const D=C.map((v,i)=>md(v+f.B[i].reduce((z,x,k)=>z+x*u[k],0)));
          ck(H.every((h,k)=>md(h.reduce((z,x,i)=>z+x*D[i],0))===s[k]),"related-syndrome identity");
          ck(md(lambda.reduce((z,x,i)=>z+x*D[i],0))===direct,"related witness identity");
        }
      }
      ck(valid>=2,"distinct valid ORIGINAL witnesses");
      report.original_valid_assignments=valid;
    }
    reports.push(report);
  }
  // Certified FALSE example g0=z0 and g1=1-z0, with e_empty=g0+g1.
  const falseB=[[0,1],[1,q-1]],E=[1,0],fRank=echelon(falseB,true);
  ck(fRank.rank===2&&fRank.H.length===0,"false certificate yields trivial syndrome");
  ck(md(falseB[0][0]+falseB[0][1])===E[0],"false cert constant");
  ck(md(falseB[1][0]+falseB[1][1])===E[1],"false cert variable");
  return {run:"MINK-SYNDROME-PROJECTION-R26",q,checks,pass:true,fixtures:reports,
    false_source:"g0=z0,g1=1-z0: e_empty in image B; no certificate supplied to simulator",
    status:"Exact affine-source normal form and reduction; NOT generic FALSE security or hard-TRUE extraction"};
}
console.log(JSON.stringify(runR26Main(),null,2));
