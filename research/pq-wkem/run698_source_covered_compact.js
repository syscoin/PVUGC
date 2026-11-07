// Exact compact regression for Run 698, over F_257; illustrative only.
const q=257,b=2,m=3,n=2*b*m+1,d=3,k=73;
let seed=69822,checks=0;
const rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed}, mod=x=>(x%q+q)%q;
const inv=x=>{let t=1;for(let h=0;h<q-2;h++)t=mod(t*x);return t};
const test=(c,msg)=>{if(!c)throw Error(msg);checks++};
const sample=(excluded,count)=>{let a=[];while(a.length<count){let v=rnd()%n;if(!excluded.includes(v)&&!a.includes(v))a.push(v)}return a};
const match=r=>r<2*b*m?[Math.floor(r/(2*b)),(r%(2*b))%b]:[0,0];
const L=[],R=[];
for(let i=0;i<m;i++){
  const l=Array.from({length:n},()=>Array(4*b).fill(0)),r=Array.from({length:4*b},()=>Array(n).fill(0));
  for(let col=0;col<4*b;col++){
    const req=col<b?Array.from({length:n},(_,x)=>x).filter(x=>{let v=match(x);return v[0]===i&&v[1]===col}):[];
    for(let row of req.concat(sample(req,d-req.length)))l[row][col]=1+rnd()%(q-1);
  }
  for(let row=0;row<4*b;row++){
    const req=row>=b&&row<2*b?Array.from({length:n},(_,x)=>x).filter(x=>{let v=match(x);return v[0]===i&&v[1]===row-b}):[];
    for(let col of req.concat(sample(req,d-req.length)))r[row][col]=req.includes(col)?rnd()%q:1+rnd()%(q-1);
  }
  L.push(l);R.push(r);
}
const Xi=Array.from({length:m},()=>Array.from({length:m+1},()=>Array.from({length:b},()=>Array.from({length:b},()=>rnd()%q))));
const gate=(i,z)=>{let G=Array.from({length:4*b},()=>Array(4*b).fill(0));let a=z[i+1],c=z[0];
  for(let p=0;p<b;p++){
    for(let [u,v,x] of [[0,0,a],[0,1,c],[1,0,a],[1,1,a],[2,2,a],[2,3,c],[3,2,a],[3,3,a]])G[u*b+p][v*b+p]=x;
    for(let t=0;t<b;t++){let x=mod(Xi[i].reduce((s,A,j)=>s+z[j]*A[p][t],0));G[p][2*b+t]=mod(-x);G[b+p][3*b+t]=x}
  }return G;
};
const mult=(A,B)=>A.map(row=>B[0].map((_,j)=>mod(row.reduce((s,x,h)=>s+x*B[h][j],0))));
const operator=z=>{let A=Array.from({length:n},()=>Array(n).fill(0));for(let i=0;i<m;i++){
  let B=mult(mult(L[i],gate(i,z)),R[i]);for(let x=0;x<n;x++)for(let y=0;y<n;y++)A[x][y]=mod(A[x][y]+B[x][y]);
}return A};
const rank=A=>{A=A.map(r=>r.slice());let h=0;for(let j=0;j<A[0].length;j++){
  let p=h;while(p<A.length&&!A[p][j])p++;if(p===A.length)continue;
  [A[h],A[p]]=[A[p],A[h]];let iv=inv(A[h][j]);for(let x=j;x<A[0].length;x++)A[h][x]=mod(iv*A[h][x]);
  for(let x=h+1;x<A.length;x++)if(A[x][j]){let v=A[x][j];for(let y=j;y<A[0].length;y++)A[x][y]=mod(A[x][y]-v*A[h][y])}
  if(++h===A.length)break;
}return h};
const e0=[1,0,0,0];let M0=operator(e0),covered=0;
for(let r=0;r<n;r++){
  let [i,p]=match(r),alpha=L[i][r][p],old=R[i][b+p][r];test(alpha!==0,'reserved alpha');
  let B=mod(M0[r][r]-alpha*old),bad=mod(-B*inv(alpha)),draw=rnd()%(q-1),fresh=draw+(draw>=bad);
  R[i][b+p][r]=fresh;let delta=mod(fresh-old);
  for(let row=0;row<n;row++)M0[row][r]=mod(M0[row][r]+L[i][row][p]*delta);
  test(M0[r][r]!==0,'diagonal covered');covered++;
}
test(JSON.stringify(M0)===JSON.stringify(operator(e0)),'exact baseline update');
const C=Array.from({length:m+1},(_,j)=>{let z=Array.from({length:m+1},(_,h)=>+(j===h)),A=operator(z);if(j===0)for(let r=0;r<n;r++)A[r][r]=mod(A[r][r]+k);return A});
for(let r=0;r<n;r++)test(C[0][r][r]!==k,'no exposed diagonal seed');
let valid=0;
for(let mask=0;mask<1<<m;mask++){
 let z=[1,...Array.from({length:m},(_,i)=>(mask>>i)&1)];
 let A=operator(z),B=Array.from({length:n},(_,r)=>Array.from({length:n},(_,c)=>mod(C.reduce((s,T,j)=>s+z[j]*T[r][c],0)-(r===c?k:0))));
 test(JSON.stringify(A)===JSON.stringify(B),'public private agreement');test(rank(A)<n,'valid source rank drop');valid++;
}
const invalidRank=rank(operator([1,2,2,2]));test(invalidRank===n,'nonboolean SOURCE is generically nonsingular');
for(let i=0;i<m;i++)for(let col=0;col<4*b;col++){
 test(L[i].filter(row=>row[col]!==0).length<=d,'L degree bound');
 test(R[i][col].filter(x=>x!==0).length<=d,'R degree bound');
}
let positions=0;for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(C.some(M=>M[r][c]!==0))positions++;
test(positions<=Math.min(n*n,n+m*(4*b*d)**2),'sparse support bound');
console.log(JSON.stringify({run:698,scope:'source-covered b=2 matrix gate correctness only; no PQ secrecy or ORIGINAL extraction',q,b,m,n,d,k,checks,covered,valid,invalidRank,positions},null,2));
