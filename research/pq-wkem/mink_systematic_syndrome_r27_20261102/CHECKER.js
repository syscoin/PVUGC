'use strict';
// R27: systematic left-kernel SOURCE normal form; no cryptographic hardness claims.
const q=257; let checks=0; let seed=2026110226;
const ck=(b,msg)=>{checks++;if(!b)throw new Error("R27 assertion " + checks + ": " + msg)};
const mod=x=>((x%q)+q)%q;
const rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};
const inv=x=>{let z=mod(x),y=1,e=q-2;ck(z!==0,'nonzero inverse');while(e){if(e&1)y=mod(y*z);z=mod(z*z);e>>=1;}return y};
function multiplyPolys(f,g){const o=new Map();for(const [a,x] of f)for(const [b,y] of g){const k=a|b;o.set(k,mod((o.get(k)||0)+x*y))}return new Map([...o].filter(x=>x[1]!==0))}
function clausePoly(cl){let p=new Map([[0,1]]);for(const [i,v] of cl)p=multiplyPolys(p,v?new Map([[0,1],[1<<i,q-1]]):new Map([[1<<i,1]]));return p}
function fixture(n,c){const clauses=[];for(let t=0;t<c;t++){const s=new Set();while(s.size<3)s.add(rnd()%n);const v=[...s],sign=v.map(()=>rnd()&1);if(sign.every(x=>x))sign[0]=0;clauses.push(v.map((x,i)=>[x,sign[i]]))}const columns=[];for(const cl of clauses){const f=clausePoly(cl);columns.push(f);for(let i=0;i<n;i++)columns.push(multiplyPolys(f,new Map([[1<<i,1]])))}const set=new Set([0]);for(const col of columns)for(const a of col.keys())set.add(a);const rows=[...set].sort((a,b)=>a-b);return {clauses,rows,B:rows.map(a=>columns.map(col=>col.get(a)||0)),n,c,L:columns.length}}
function rowElim(B,track=false){const m=B.length,L=B[0].length,A=B.map(r=>r.slice()),order=Array.from({length:m},(_,i)=>i);const T=track?Array.from({length:m},(_,i)=>Array.from({length:m},(_,j)=>+(i===j))):null;let rank=0;
  for(let j=0;j<L&&rank<m;j++){let p=rank;while(p<m&&!A[p][j])p++;if(p===m)continue;[A[rank],A[p]]=[A[p],A[rank]];[order[rank],order[p]]=[order[p],order[rank]];if(T)[T[rank],T[p]]=[T[p],T[rank]];const z=inv(A[rank][j]);for(let k=j;k<L;k++)A[rank][k]=mod(A[rank][k]*z);if(T)for(let k=0;k<m;k++)T[rank][k]=mod(T[rank][k]*z);for(let i=rank+1;i<m;i++)if(A[i][j]){const z=A[i][j];for(let k=j;k<L;k++)A[i][k]=mod(A[i][k]-z*A[rank][k]);if(T)for(let k=0;k<m;k++)T[i][k]=mod(T[i][k]-z*T[rank][k])}rank++}
  if(T)for(let i=rank;i<m;i++)ck(A[i].every(x=>x===0),'old basis is kernel');return {rank,pivots:order.slice(0,rank),H:T?T.slice(rank):null}}
function inverse(A){const n=A.length;if(!n)return [];const C=A.map((r,i)=>r.concat(Array.from({length:n},(_,j)=>+(i===j))));for(let j=0;j<n;j++){let p=j;while(p<n&&!C[p][j])p++;ck(p<n,'pivot inverse');[C[j],C[p]]=[C[p],C[j]];let z=inv(C[j][j]);for(let k=j;k<2*n;k++)C[j][k]=mod(z*C[j][k]);for(let i=0;i<n;i++)if(i!==j&&C[i][j]){z=C[i][j];for(let k=j;k<2*n;k++)C[i][k]=mod(C[i][k]-z*C[j][k])}}return C.map(r=>r.slice(n))}
function systematic(B,old){const m=B.length,L=B[0].length,rank=old.rank,P=old.pivots,N=Array.from({length:m},(_,i)=>i).filter(x=>!P.includes(x));const Pmat=P.map(i=>B[i]);const colP=rowElim(Array.from({length:L},(_,j)=>Pmat.map(r=>r[j])),false).pivots;ck(colP.length===rank,'selected independent columns');const G=Pmat.map(r=>colP.map(j=>r[j])),Ginv=inverse(G);const A=N.map(i=>{const coords=colP.map(j=>B[i][j]);const alpha=Ginv[0].map((_,j)=>mod(coords.reduce((s,x,k)=>s+x*Ginv[k][j],0)));for(let t=0;t<L;t++)ck(mod(alpha.reduce((s,x,k)=>s+x*B[P[k]][t],0))===B[i][t], 'row representation');return alpha});return {P,N,A,rank}}
const dot=(u,v)=>mod(u.reduce((s,x,i)=>s+x*v[i],0));
function synd(s,v){return s.N.map((i,j)=>mod(v[i]-dot(s.A[j],s.P.map(p=>v[p]))))}
function rankOf(A){if(!A.length)return 0;return rowElim(A,false).rank}
const output=[];
for(const [n,c] of [[8,12],[10,20]]){
  const f=fixture(n,c),old=rowElim(f.B,true),sys=systematic(f.B,old);const m=f.rows.length,r=sys.rank,k=m-r;
  ck(k>0&&r>0,'nondegenerate');ck(sys.N.length===k,'nonpivot rank');
  const W=old.H.map(h=>sys.N.map(j=>h[j]));ck(rankOf(W)===k,'basis transform invertible');
  const trials=n===8?256:64;let valid=0, witnessTests=0;
  for(let a=0;a<trials;a++){
    const v=Array.from({length:m},()=>rnd()%q);
    const sig=synd(sys,v);const ref=old.H.map(h=>dot(h,v));
    for(let t=0;t<k;t++)ck(ref[t]===dot(W[t],sig),'R26 transformation of full public syndrome');
    const mask=Array.from({length:f.L},()=>rnd()%q);
    const shifted=v.map((x,i)=>mod(x+dot(f.B[i],mask)));
    ck(synd(sys,shifted).every((x,j)=>x===sig[j]),'R22 public mask derivative gives same sigma');
    for(let j=0;j<k;j++)ck(mod(sig[j]+dot(sys.A[j],sys.P.map(i=>v[i])))===v[sys.N[j]],'canonical systematic section identity');
  }
  if(n===8){for(let a=0;a<(1<<n);a++){const ok=f.clauses.every(cl=>cl.some(([i,positive])=>((a>>i)&1)===positive));if(!ok)continue;valid++;const lambda=f.rows.map(row=>+((a&row)===row));for(let col=0;col<f.L;col++)ck(dot(lambda,f.B.map(row=>row[col]))===0,'ORIGINAL witness annihilation');const e=Array.from({length:m},()=>rnd()%3-1),mu=rnd()%2,delta=120;
    const z=e.map((x,i)=>mod(x+(f.rows[i]===0?delta*mu:0))),sigma=synd(sys,z),omega=sys.N.map(i=>lambda[i]);
    ck(dot(omega,sigma)===dot(lambda,z),'zero-elimination witness decode');
    ck(dot(omega,sigma)===mod(delta*mu+lambda.reduce((s,x,i)=>s+x*e[i],0)),'SAME original capability and noise');
    witnessTests++;
  }}
  output.push({n,c,m,rank:r,k,old_kernel_material:m*k,systematic_kernel_material:k*r,
    stored_element_reduction_percent:Number((100*k/m).toFixed(3)),
    old_witness_coordinates: m + "x" + k + " Gaussian solve",new_witness_coordinates:k + " direct Boolean evaluations",
    valid_witnesses_checked:valid,witness_tests:witnessTests,uniform_public_trials:trials});
}
const out={run:'MINK-SYSTEMATIC-SYNDROME-R27',q,checks,pass:true,fixtures:output,
  theorem:'Systematic H=[-A | I] in (P,N) row order; H_old=W*H_sys, W invertible',
  security:'QPT-equivalent ONLY to R26 source, not new SOURCE confidentiality or hard-TRUE extraction'};
console.log(JSON.stringify(out,null,2));
