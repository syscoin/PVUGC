function boundedCheckR143(){
 const q=257,d=6,r=3,L=4;let checks=0,fixtures=0,good=0,bad=0;
 const mod=x=>(x%q+q)%q;
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 function ok(cond,descr){checks++;if(!cond)throw Error("check "+checks+": "+descr);}
 const I=n=>Array.from({length:n},(_,i)=>Array.from({length:n},(_,j)=>+(i===j)));
 function mul(A,B){const n=A.length,p=B.length,m=B[0].length;ok(A[0].length===p,"dimensions");return Array.from({length:n},(_,i)=>Array.from({length:m},(_,j)=>mod(A[i].reduce((s,a,k)=>s+a*B[k][j],0))));}
 function pow(a,e){let t=1;while(e){if(e&1)t=mod(t*a);a=mod(a*a);e>>=1;}return t;}
 function inv(X){let n=X.length,A=X.map((row,i)=>[...row,...I(n)[i]]);for(let c=0;c<n;c++){let p=c;while(p<n&&!A[p][c])p++;if(p===n)return null;[A[c],A[p]]=[A[p],A[c]];let scale=pow(A[c][c],q-2);A[c]=A[c].map(v=>mod(v*scale));for(let k=0;k<n;k++)if(k!==c){let a=A[k][c];A[k]=A[k].map((v,j)=>mod(v-a*A[c][j]));}}return A.map(row=>row.slice(n));}
 const label=M=>M.flat().reduce((a,v)=>(a*131+v)%65536,0);
 for(let f=0;f<48;f++){
  let seed=(14300+f)>>>0;
  function rnd(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return(seed>>>0)%q;}
  function randomGL(){for(let i=0;i<10000;i++){let G=Array.from({length:r},()=>Array.from({length:r},rnd));let Gi=inv(G);if(Gi)return[G,Gi];}throw Error("GL draw");}
  function frame(){let [X,Xi]=randomGL();let U=X.concat(Array.from({length:d-r},()=>Array.from({length:r},rnd)));let V=Xi.map(row=>row.concat(Array(d-r).fill(0)));ok(eq(mul(V,U),I(r)),"split frame");return [U,V];}
  const [g,gi]=randomGL(),[h,hi]=randomGL();
  const alpha=mul(mul(mul(g,h),gi),hi);
  if(eq(alpha,I(r)))throw Error("random generators commute");
  let F=Array.from({length:L},frame);F.push(F[0]);
  let H=[[I(r),g],[I(r),h],[I(r),gi],[I(r),hi]];
  let A=H.map((pair,i)=>pair.map(M=>mul(mul(F[i][0],M),F[i+1][1])));
  function path(bits){let P=I(d);for(let i=0;i<L;i++)P=mul(P,A[i][bits[i]]);return P;}
  const P0=path([0,0,0,0]),B=mul(mul(F[0][0],alpha),F[0][1]);
  ok(eq(P0,mul(F[0][0],F[0][1])),"baseline projector");
  ok(eq(mul(P0,P0),P0),"idempotent projector");
  let E=[];
  for(let i=0;i<L;i++){let v=[0,0,0,0];v[i]=1;E.push(path(v));ok(eq(E[i],mul(mul(F[0][0],H[i][1]),F[0][1])),"public isolated occurrence");}
  let Bfake=E.reduce((acc,M)=>mul(acc,M),I(d));
  ok(eq(Bfake,B),"public accepting word synthesizes same matrix");
  for(let x=0;x<=1;x++)for(let y=0;y<=1;y++){
   let P=path([x,y,x,y]);ok(eq(P,(x&&y)?B:P0),"TRUE original path semantics");
   if(x&&y){let secret=1000+f,cipher=secret^label(B);ok((cipher^label(P))===secret,"valid release");good++;}
  }
  for(let x=0;x<=1;x++)ok(eq(path([x,1-x,x,1-x]),P0),"FALSE original has no accepting path");
  let key=2000+f,ct=key^label(B);
  ok((ct^label(Bfake))===key,"public FALSE capability recovery");
  ok(!eq(B,P0),"nontrivial accepting matrix");bad++;fixtures++;
 }
 return {run:"R143",field:q,ambient_dimension:d,support_rank:r,fixtures,assertions:checks,legitimate_true_releases:good,false_public_bypasses:bad,status:"REJECTED: nonlinear rank-deficient support frames remain publicly composable"};
}

if (typeof module !== 'undefined' && require.main === module) console.log(JSON.stringify(boundedCheckR143(),null,2));
