const report=(function run697(){
 const q=257,k=17,counts={assertions:0,witnesses:0,recoveries:0,public_equals_private:0,lossless_decodings:0},fixtures=[];
 const mod=x=>(x%q+q)%q;
 const pow=(x,e)=>{let z=1;while(e>0){if(e%2)z=mod(z*x);x=mod(x*x);e=Math.floor(e/2)}return z};
 const check=(condition,message)=>{if(!condition)throw Error(message);counts.assertions++};
 const add=(a,idx,x)=>a.set(idx,mod((a.get(idx)||0)+x));
 const matvec=(A,v,n)=>{let out=Array(n).fill(0);for(let [ij,x] of A)out[Math.floor(ij/n)]=mod(out[Math.floor(ij/n)]+x*v[ij%n]);return out};
 const bm=s=>{let C=[1],B=[1],L=0,j=1,b=1;for(let t=0;t<s.length;t++){let d=mod(s[t]+Array.from({length:L},(_,h)=>C[h+1]*s[t-h-1]).reduce((x,y)=>x+y,0));if(!d){j++;continue}let old=C.slice(),ratio=mod(d*pow(b,q-2));while(C.length<B.length+j)C.push(0);for(let h=0;h<B.length;h++)C[h+j]=mod(C[h+j]-ratio*B[h]);if(2*L<=t){L=t+1-L;B=old;b=d;j=1}else j++}return C.slice(0,L+1)};
 const root=(f,x)=>f.reduce((v,c)=>mod(v*x+c),0)===0;
 const rank=(A,n)=>{A=A.map(r=>r.slice());let h=0;for(let c=0;c<n;c++){let p=h;while(p<n&&!A[p][c])p++;if(p===n)continue;[A[h],A[p]]=[A[p],A[h]];let iv=pow(A[h][c],q-2);for(let j=c;j<n;j++)A[h][j]=mod(A[h][j]*iv);for(let i=h+1;i<n;i++)if(A[i][c]){let t=A[i][c];for(let j=c;j<n;j++)A[i][j]=mod(A[i][j]-t*A[h][j])}if(++h===n)break}return h};
 for(let m of [3,4,5]){
  let n=2*m+1,d=3,state=(0x7f4a7c15+m)>>>0;
  const rnd=()=>{state=(Math.imul(1664525,state)+1013904223)>>>0;return state};
  const nz=()=>1+rnd()%(q-1), row=()=>rnd()%n;
  const support=()=>{let used=new Set,arr=[];while(arr.length<d){let r=row();if(!used.has(r)){used.add(r);arr.push([r,nz()])}}return arr};
  let L=Array.from({length:m},()=>Array.from({length:4},support));
  let R=Array.from({length:m},()=>Array.from({length:4},support));
  let xi=Array.from({length:m},()=>Array.from({length:m+1},()=>rnd()%q));
  const gate=(i,j,x)=>{let a=(j===i+1)?1:0,c=(j===0)?1:0;return [[a,c,-x,0],[a,a,0,x],[0,0,a,c],[0,0,a,a]]};
  const combine=(coeff,z)=>{let A=new Map;coeff.forEach((C,j)=>{if(!z[j])return;for(let [ij,v] of C)add(A,ij,z[j]*v)});for(let [ij,v] of A)if(!v)A.delete(ij);return A};
  const addgate=(A,i,G)=>{for(let p=0;p<4;p++)for(let t=0;t<4;t++)if(G[p][t])for(let [rr,u] of L[i][p])for(let [cc,v] of R[i][t])add(A,rr*n+cc,u*G[p][t]*v)};
  const coeff=Array.from({length:m+1},(_,j)=>{let A=new Map;for(let i=0;i<m;i++)addgate(A,i,gate(i,j,xi[i][j]));if(!j)for(let r=0;r<n;r++)add(A,r*n+r,k);for(let [ij,v] of A)if(!v)A.delete(ij);return A});
  const edges=[...new Set(coeff.flatMap(A=>[...A.keys()]))].sort((a,b)=>a-b);
  const values=coeff.map(A=>edges.map(ij=>A.get(ij)||0));
  check(values.every((v,j)=>v.every((x,h)=>x===(coeff[j].get(edges[h])||0))),'lossless encoded matrix');
  counts.lossless_decodings++;
  for(let mask=0;mask<(1<<m);mask++){
   const z=[1,...Array.from({length:m},(_,i)=>(mask>>i)&1)],Pub=combine(coeff,z),Priv=new Map;
   for(let i=0;i<m;i++){let X=mod(xi[i].reduce((t,c,j)=>t+c*z[j],0)),a=z[i+1],c=1;addgate(Priv,i,[[a,c,-X,0],[a,a,0,X],[0,0,a,c],[0,0,a,a]])}
   for(let r=0;r<n;r++)add(Priv,r*n+r,k);
   for(let [ij,v] of Priv)if(!v)Priv.delete(ij);
   check(Pub.size===Priv.size && [...Pub].every(([ij,v])=>Priv.get(ij)===v),'independent public/private evaluation');
   counts.public_equals_private++;counts.witnesses++;
   let B=Array.from({length:n},()=>Array(n).fill(0));for(let [ij,v] of Pub)B[Math.floor(ij/n)][ij%n]=v;
   for(let r=0;r<n;r++)B[r][r]=mod(B[r][r]-k);
   check(rank(B,n)<n,'every valid witness gives K eigenvalue');
   if(mask<4){
    let found=false;
    for(let trial=0;trial<8;trial++){
     let u=Array.from({length:n},()=>rnd()%q),v=Array.from({length:n},()=>rnd()%q),s=[];
     for(let it=0;it<2*n;it++){s.push(mod(u.reduce((t,a,j)=>t+a*v[j],0)));if(it+1<2*n)v=matvec(Pub,v,n)}
     let recurrence=bm(s);
     if(root(recurrence,k)){found=true;break}
    }
    check(found,'fresh Krylov root recovery');counts.recoveries++;
   }
  }
  fixtures.push({gates:m,n,degree:d,public_common_edges:edges.length,dense_per_slice:n*n,valid_witnesses:1<<m});
 }
 let m=15000,d=3,n=2*m+1,slices=m+2,edges=Math.min(n*n,n+m*16*d*d),denseBytes=slices*n*n*32,sparseBytes=slices*edges*32+edges*4;
 check(sparseBytes<denseBytes,'asymptotic common-support compression');
 return {run:697,scope:'exact sparse public pencil correctness and representation only; QPT security unproved',field:q,counts,fixtures,illustrative:{gates:m,degree:d,slices,common_edges_upper:edges,dense_bytes:denseBytes,sparse_bytes_upper:sparseBytes,compression_lower:Math.floor(100*denseBytes/sparseBytes)/100}};
})();
console.log(JSON.stringify(report,null,2));
