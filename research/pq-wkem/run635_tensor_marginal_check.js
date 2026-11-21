function runCheck() {
  let checks=0; function ok(c,msg){checks++;if(!c)throw Error(msg);}
  const I=[[1n,0n],[0n,1n]], X=[[0n,1n],[1n,0n]];
  function mm(A,B){return A.map(row=>B[0].map((_,j)=>row.reduce((s,a,k)=>s+a*B[k][j],0n)));}
  function rm(row,M){return M[0].map((_,j)=>row.reduce((s,a,k)=>s+a*M[k][j],0n));}
  function mc(M,col){return M.map(row=>row.reduce((s,a,k)=>s+a*col[k],0n));}
  function dot(a,b){return a.reduce((s,x,i)=>s+x*b[i],0n);}
  function kron(A,B){let ret=[];for(let a of A)for(let b of B)ret.push(a.flatMap(x=>b.map(y=>x*y)));return ret;}
  function kv(a,b){return a.flatMap(x=>b.map(y=>x*y));}
  function inv(G){ok(G[0][0]*G[1][1]-G[0][1]*G[1][0]===1n,"det");return [[G[1][1],-G[0][1]],[-G[1][0],G[0][0]]];}
  function rng(seed){let s=seed>>>0;return n=>{s^=(s<<13);s^=s>>>17;s^=(s<<5);return (s>>>0)%n;};}
  function frame(r){let g=I;for(let j=0;j<5;j++){let a=BigInt((r(2)?1:-1)*(r(2)+1));let t=r(2)?[[1n,a],[0n,1n]]:[[1n,0n],[a,1n]];g=mm(g,t);}ok(JSON.stringify(g.map(v=>v.map(String)))!=="" ,"frame");return g;}
  function chain(n,d,r){let F=Array.from({length:n+1},()=>frame(r));let edges=[];for(let i=0;i<n;i++){let invG=inv(F[i]);edges.push([mm(mm(invG,d[i]?X:I),F[i+1]),mm(mm(invG,d[i]?I:X),F[i+1])]);}return {row:rm([1n,0n],F[0]),edges,last:inv(F[n])};}
  function contract(A,R,num,den,k){let v=kv(A.row,R.row);for(let i=0;i<A.edges.length;i++){let U=kron(A.edges[i][0],R.edges[i][0]),V=kron(A.edges[i][1],R.edges[i][1]);v=rm(v,U.map((row,j)=>row.map((a,h)=>a+V[j][h])));}return dot(v,kv(mc(A.last,[BigInt(den),BigInt(num)]),mc(R.last,k?[0n,1n]:[1n,0n])));}
  function direct(A,R,num,den,w,k){let av=A.row,rv=R.row;for(let i=0;i<w.length;i++){av=rm(av,A.edges[i][w[i]]);rv=rm(rv,R.edges[i][w[i]]);}return dot(av,mc(A.last,[BigInt(den),BigInt(num)]))*dot(rv,mc(R.last,k?[0n,1n]:[1n,0n]));}
  let fixtures=[];
  for(let [seed,n,num,den] of [[11,5,0,1],[17,8,1,8],[23,9,1,2],[31,12,1,1],[47,18,2,1]]) {
    let r=rng(seed),A=chain(n,Array(n).fill(0),r),key=[],rec=[];
    for(let j=0;j<6;j++) {
      let K=r(2), d=Array.from({length:n-1},()=>r(2));d.push(K^d.reduce((a,b)=>a^b,0));
      let R=chain(n,d,r),z0=contract(A,R,num,den,0),z1=contract(A,R,num,den,1),half=1n<<BigInt(n-1);
      ok(z0===(K?BigInt(num)*half:BigInt(den)*half),"marginal0");
      ok(z1===(K?BigInt(den)*half:BigInt(num)*half),"marginal1");
      let samples=n<=9?(1<<n):5;
      for(let x=0;x<samples;x++){let v=n<=9?x:[0,1,3,(1<<n)-1,Math.floor((1<<n)/3)][x];let w=Array.from({length:n},(_,i)=>(v>>i)&1),p=w.reduce((a,b)=>a^b,0);for(let k=0;k<2;k++){ok(direct(A,R,num,den,w,k)===BigInt(p?num:den)*BigInt((k===(p^K))?1:0),"direct");}}
      key.push(K);rec.push(z0>z1?0:z1>z0?1:null);
    }
    ok(rec.every((v,i)=>num<den?v===key[i]:num==den?v===null:v===1-key[i]),"dominance");
    fixtures.push({n,seed,eta:`${num}/${den}`,key:key.join(""),contracted:rec.map(v=>v===null?"?":v).join(""),exhaustive:n<=9});
  }
  return {run:635,checks_passed:checks,model:"integer unimodular two-state gauge chains, four-state public transfer",fixtures,security_claim:"finite algebra only, no hard SOURCE or native PQ signatures"};
}
console.log(JSON.stringify(runCheck(),null,2));
