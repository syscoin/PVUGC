const run = function run(){
  const Q=65537,G=Math.floor(Q/256);let seed=20261031,checks=0, compromised=0, cases=0;
  function next(){seed=(Math.imul(1664525,seed)+1013904223)>>>0;return seed;}
  function rnd(n){return next()%n;}
  function check(ok,msg){if(!ok)throw Error(msg);checks++;}
  function clausesFor(caseNo){
    if(caseNo===0)return {n:1,cs:[[[0,1],[0,1],[0,1]],[[0,0],[0,0],[0,0]]]};
    let n=1+rnd(5),m=1+rnd(6),cs=[];
    for(let j=0;j<m;j++){let c=[];for(let k=0;k<3;k++)c.push([rnd(n),rnd(2)]);cs.push(c);}
    return {n,cs};
  }
  function good(w,cs){return cs.every(c=>c.some(([i,p])=>p?w[i]:1-w[i]));}
  function build(n,cs,oneHot){
    let m=cs.length,N=n+(oneHot?3:2)*m,D=oneHot?2*m:m;
    let A=Array.from({length:D},()=>Array(N).fill(0)),t=[];
    cs.forEach((c,j)=>{
      let neg=0;for(const [i,p]of c){A[oneHot?2*j:j][i]+=p?1:-1;if(!p)neg++;}
      if(oneHot){A[2*j][n+3*j]=3;A[2*j][n+3*j+1]=2;A[2*j][n+3*j+2]=1;
        for(let a=0;a<3;a++)A[2*j+1][n+3*j+a]=1;t.push(4-neg,1);}
      else{A[j][n+2*j]=1;A[j][n+2*j+1]=2;t.push(4-neg);}
    });return {A,t,N,D};
  }
  function ext(w,cs,oneHot,fake){
    let z=w.slice();
    for(const c of cs){
      let k=c.reduce((sum,[i,p])=>sum+(p?w[i]:1-w[i]),0);
      if(k===0&&!fake)return null;
      if(oneHot)z.push(...(k===0?[2,-1,0]:k===1?[1,0,0]:k===2?[0,1,0]:[0,0,1]));
      else{let x=4-k;z.push(...(x===4?[0,2]:[x%2,Math.floor(x/2)]));}
    }return z;
  }
  function mult(A,z){return A.map(row=>row.reduce((s,x,i)=>s+x*z[i],0));}
  function same(x,y){return x.length===y.length&&x.every((v,i)=>v===y[i]);}
  function mix(A,t){
    let d=A.length,U=Array.from({length:d},()=>Array(d).fill(0));
    for(let i=0;i<d;i++){U[i][i]=1+rnd(Q-1);for(let j=i+1;j<d;j++)U[i][j]=rnd(Q);}
    return {A:U.map(row=>A[0].map((_,k)=>row.reduce((s,v,j)=>s+v*A[j][k],0)%Q)),
      t:U.map(row=>row.reduce((s,v,j)=>s+v*t[j],0)%Q)};
  }
  function decrypt(A,t,z,u){
    let d=A.length,N=A[0].length,s=Array.from({length:d},()=>rnd(Q)),
      e=Array.from({length:N},()=>rnd(3)-1),es=rnd(3)-1;
    let beta=Array.from({length:N},(_,i)=>(A.reduce((v,row,j)=>v+row[i]*s[j],0)+e[i])%Q);
    let tau=(t.reduce((v,x,j)=>v+x*s[j],0)+es+G*u)%Q;
    let residue=((tau-z.reduce((v,x,i)=>v+x*beta[i],0))%Q+Q)%Q;
    let best=0,dist=Infinity;
    for(let x=0;x<256;x++){let diff=(residue-G*x+Q*256)%Q;let delta=Math.min(diff,Q-diff);if(delta<dist){dist=delta;best=x;}}
    return best;
  }
  for(let j=0;j<34;j++){
    let {n,cs}=clausesFor(j);cases++;
    for(const oneHot of [false,true]){
      let {A,t,N}=build(n,cs,oneHot),wAll=Array(n).fill(1),zf=ext(wAll,cs,oneHot,true);
      check(same(mult(A,zf),t),"public nonbinary opening");
      check(zf.some(v=>v<0||v>1)||good(wAll,cs),"nonbinary when all-ones invalid");
      let available=[];
      for(let mask=0;mask<(1<<n);mask++){
        let w=Array.from({length:n},(_,i)=>(mask>>i)&1),z=ext(w,cs,oneHot,false);
        check((z!==null)===good(w,cs),"binary completeness");
        if(z){check(same(mult(A,z),t),"binary source soundness");available.push(z);}
      }
      let transformed=mix(A,t);
      check(same(mult(transformed.A,zf).map(x=>(x%Q+Q)%Q),transformed.t),"row scramble");
      for(let s=0;s<12;s++){
        let u=rnd(256);
        check(decrypt(A,t,zf,u)===u,"raw false key recovery");
        check(decrypt(transformed.A,transformed.t,zf,u)===u,"mixed false key recovery");
        if(available.length)check(decrypt(A,t,available[rnd(available.length)],u)===u,"honest release");
        compromised++;
      }
    }
  }
  return {candidate:"CORN v1 and v2: public alternative opening",checks,cases,compromised_symbols:compromised,chosen_false_instance:"(x or x or x) and (!x or !x or !x)",quantum_security_claim:false};
};
console.log(JSON.stringify(run(),null,2));
