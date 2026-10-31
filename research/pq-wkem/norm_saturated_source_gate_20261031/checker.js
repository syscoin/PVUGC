const runChecker = function runChecker(){
  let assertions=0;
  function ok(cond,msg){if(!cond)throw new Error("ASSERTION: "+msg); assertions++;}
  const q=65537,B=1;
  function compile(n,clauses){
    let m=clauses.length,P=n+2*m,N=2*P,A=[],t=[];
    for(let j=0;j<P;j++){let row=Array(N).fill(0);row[2*j]=1;row[2*j+1]=1;A.push(row);t.push(1);}
    for(let c=0;c<m;c++){let row=Array(N).fill(0);
      for(let lit of clauses[c])row[2*(Math.abs(lit)-1)+(lit>0?1:0)]++;
      row[2*(n+2*c)+1]--;row[2*(n+2*c+1)+1]-=2;
      A.push(row);t.push(1);
    }return {n,m,P,A,t};
  }
  function lift(C,w){
    let z=[];
    for(let a of w)z.push(1-a,a);
    let misses=0;
    for(let cl of C.clauses){
      let L=cl.reduce((s,lit)=>s+(lit>0?w[lit-1]:1-w[-lit-1]),0);
      if(L===0)misses++;
      let s=L-1,lo=s<0?s:s%2,hi=s<0?0:Math.floor(s/2);
      z.push(1-lo,lo,1-hi,hi);
    }return {z,misses};
  }
  function dot(x,y){let v=0;for(let i=0;i<x.length;i++)v+=x[i]*y[i];return v;}
  function matrix(A,z){return A.map(a=>dot(a,z));}
  function norm2(z){return dot(z,z);}
  function norm1(z){return z.reduce((s,x)=>s+Math.abs(x),0);}
  function cen(x){let y=((x%q)+q)%q;return y>q/2?y-q:y;}
  let seed=20261031;
  function rnd(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
  function int(n){return rnd()%n;}
  function cipher(C,bit,g){
    let R=C.A.length,N=C.A[0].length,s=Array.from({length:R},()=>int(q));
    let e=Array.from({length:N},()=>int(3)-1),star=int(3)-1;
    let beta=e.slice();
    for(let i=0;i<R;i++)for(let j=0;j<N;j++)if(C.A[i][j])beta[j]+=C.A[i][j]*s[i];
    beta=beta.map(x=>((x%q)+q)%q);
    let tau=((dot(C.t,s)+g*bit+star)%q+q)%q;
    return {beta,tau,e,star};
  }
  function recover(Cipher,z,g){
    const r=cen(dot(Cipher.beta,z)-Cipher.tau);
    return {bit:Math.abs(r)<Math.abs(r+g)?0:1,res:r};
  }
  let clauses=[];
  for(let t=0;t<4;t++)for(let mask=0;mask<8;mask++)clauses.push([0,1,2].map(i=>(i+1)*((mask>>i)&1?1:-1)));
  let C=compile(3,clauses); C.clauses=clauses;
  ok(C.P===67&&C.A.length===99&&C.A[0].length===134,"dimensions");
  for(let mask=0;mask<8;mask++){
    let W=[0,1,2].map(j=>(mask>>j)&1),{z,misses}=lift(C,W);
    ok(misses===4,"false polarity formula");
    ok(matrix(C.A,z).every((x,i)=>x===C.t[i]),"false affine equations");
    ok(norm2(z)===83&&norm1(z)===75,"false norm gap");
  }
  const fake=lift(C,[0,0,0]).z,g=2*B*(C.P+1)+1;
  let master=Array.from({length:512},()=>int(2)),errors=[];
  for(let k of master){
    const v=cipher(C,k,g),rec=recover(v,fake,g),delta=dot(v.e,fake)-v.star;
    ok(cen(rec.res+g*k)===delta,"joint source exact residual");
    ok(rec.bit===k,"unauthorized false key");
    errors.push(Math.abs(delta));
  }
  let trueClauses=[[1,2,3],[-1,2,3]],T=compile(3,trueClauses);T.clauses=trueClauses;
  let valid=[];
  for(let mask=0;mask<8;mask++){
    let w=[0,1,2].map(j=>(mask>>j)&1),zz=lift(T,w);
    if(zz.misses===0){
      ok(norm2(zz.z)===T.P&&matrix(T.A,zz.z).every((x,i)=>x===T.t[i]),"valid original certificate");
      valid.push(zz.z);
    }
  }
  ok(valid.length===6,"six original witnesses");
  const gt=2*(T.P+1)+1;
  for(let k of master){
    let v=cipher(T,k,gt);
    for(let z of valid){
      let rec=recover(v,z,gt);
      ok(rec.bit===k,"all witness same key");
      ok(Math.abs(cen(rec.res+gt*k))<=T.P+1,"honest deterministic bound");
    }
  }
  const rho=2*Math.exp(-((g/2)**2)/(2*(norm2(fake)+1)));
  ok(512*rho<1e-8,"exact Hoeffding fixed fake bound");
  return {assertions,disposition:"REJECTED; full 512-bit key recovered for FALSE 3CNF",false_instance:{n:3,clauses:32,original_satisfying_assignments:0,rows:99,cols:134,pairs:67},q,B,g,public_fake:{norm_squared:83,norm_l1:75},recovered_bits:512,max_absolute_fake_noise:Math.max(...errors),union_bound_512:512*rho,true_witnesses:valid.length,true_release_evaluations:valid.length*512};
};
console.log(JSON.stringify(runChecker(), null, 2));
