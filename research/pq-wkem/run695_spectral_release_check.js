// Run 695. Deterministic exact finite-field spectral-release checks.
// Only correctness/algebra is exercised. The toy checker is openly invertible.
const report=(()=>{
 const q=101,m=2,n=2*m+1,k=17; let assertions=0,cases=0;
 const mod=x=>((x%q)+q)%q, must=(p,s)=>{if(!p)throw Error(s);assertions++};
 const zero=(h,w)=>Array.from({length:h},()=>Array(w).fill(0));
 const id=h=>Array.from({length:h},(_,i)=>Array.from({length:h},(_,j)=>+(i===j)));
 const add=(A,B)=>A.map((r,i)=>r.map((x,j)=>mod(x+B[i][j])));
 const scale=(A,x)=>A.map(r=>r.map(y=>mod(x*y)));
 const mul=(A,B)=>A.map(r=>B[0].map((_,j)=>mod(r.reduce((s,x,i)=>s+x*B[i][j],0))));
 const pow=(a,e)=>{let v=1;while(e){if(e%2)v=mod(v*a);a=mod(a*a);e=Math.floor(e/2)}return v};
 const det=A=>{let B=A.map(r=>r.slice()),d=1;
   for(let j=0;j<B.length;j++){let r=j;while(r<B.length&&!mod(B[r][j]))r++;
    if(r===B.length)return 0;if(r!==j){[B[j],B[r]]=[B[r],B[j]];d=-d}
    let v=mod(B[j][j]);d=mod(d*v);let z=pow(v,q-2);
    for(let i=j+1;i<B.length;i++){let f=mod(B[i][j]*z);
      for(let t=j;t<B.length;t++)B[i][t]=mod(B[i][t]-f*B[j][t]);}}
   return mod(d);};
 const rref=A=>{let B=A.map(r=>r.map(mod)),pivot=[],row=0;
   for(let j=0;j<B[0].length;j++){let t=row;while(t<B.length&&!B[t][j])t++;
    if(t===B.length)continue;[B[t],B[row]]=[B[row],B[t]];
    let z=pow(B[row][j],q-2);B[row]=B[row].map(v=>mod(z*v));
    for(let i=0;i<B.length;i++)if(i!==row){let f=B[i][j];B[i]=B[i].map((v,c)=>mod(v-f*B[row][c]))}
    pivot.push(j);row++;if(row===B.length)break;}
   return {B,pivot,rank:row};};
 const nullvec=A=>{let {B,pivot}=rref(A),v=Array(A[0].length).fill(0),free=v.findIndex((_,i)=>!pivot.includes(i));must(free>=0,'nonzero kernel');
   v[free]=1;for(let i=pivot.length-1;i>=0;i--){let j=pivot[i],s=0;for(let c=j+1;c<v.length;c++)s+=B[i][c]*v[c];v[j]=mod(-s)}
   must(A.every(r=>mod(r.reduce((s,x,i)=>s+x*v[i],0))===0),'kernel verification');return v;};
 const rng=seed=>{let z=seed>>>0;return ()=>{z=(Math.imul(1664525,z)+1013904223)>>>0;return z%q}};
 const material=seed=>{let r=rng(seed);return Array.from({length:m},()=>({
    L:Array.from({length:n},()=>Array.from({length:4},()=>r())),
    R:Array.from({length:4},()=>Array.from({length:n},()=>r())),
    x:Array.from({length:m+1},()=>r())}));};
 const gate=(w,i,x)=>{let a=w[i+1],c=w[0],z=mod(w.reduce((s,v,j)=>s+v*x[j],0));
   return [[a,c,mod(-z),0],[a,a,0,z],[0,0,a,c],[0,0,a,a]]};
 const source=(w,M)=>M.reduce((A,g,i)=>add(A,mul(mul(g.L,gate(w,i,g.x)),g.R)),zero(n,n));
 const basis=Array.from({length:m+1},(_,j)=>Array.from({length:m+1},(_,i)=>+(i===j)));
 const pub=M=>basis.map((b,j)=>add(source(b,M),j===0?scale(id(n),k):zero(n,n)));
 const evaluate=(C,w)=>C.reduce((A,P,j)=>add(A,scale(P,w[j])),zero(n,n));
 const roots=A=>{let out=[];for(let z=0;z<q;z++)if(det(add(A,scale(id(n),-z)))===0)out.push(z);return out};
 const toyTag=x=>pow(x,3),tag=toyTag(k);
 for(let z=0;z<q;z++)must((toyTag(z)===tag)===(z===k),'toy filter uniqueness');
 const witnesses=[[1,0,0],[1,0,1],[1,1,0],[1,1,1]];
 for(let seed=1;seed<=12;seed++){
   let M=material(seed),C=pub(M);
   for(let w of witnesses){let B=source(w,M),A=evaluate(C,w),r=roots(A);
     must(rref(B).rank<=n-1,'valid source singular');
     must(JSON.stringify(A)===JSON.stringify(add(B,scale(id(n),k))),'linear ciphertext');
     must(r.includes(k),'key is a generalized eigenvalue');
     let selected=r.filter(z=>toyTag(z)===tag);must(selected.length===1&&selected[0]===k,'all-witness same-key');
     cases++;}}
 let regression=null;
 for(let seed=40;seed<120&&!regression;seed++){
   let M=material(seed),w=witnesses[3],B=source(w,M);
   if(rref(B).rank!==n-1)continue;
   let v=nullvec(B),j=v.findIndex((x,i)=>i<n-1&&x!==0);if(j<0)continue;
   let P=id(n);P[n-1][j]=mod(v[n-1]*pow(v[j],q-2));
   must(det(P)===1,'invertible right shear');
   let adj=M.map(g=>({...g,R:mul(g.R,P)})),B2=source(w,adj);
   must(rref(B2).rank===n-1,'shear preserves rank');
   let cof=det(B2.slice(0,n-1).map(r=>r.slice(0,n-1)));
   must(cof===0,'prior rank-one cofactor intentionally zero');
   let C=pub(adj),r=roots(evaluate(C,w));
   must(r.includes(k),'full-rank pencil retains key');
   for(let t=0;t<q;t++){let E=zero(n,n);E[n-1][n-1]=1;
      must(det(add(B2,scale(E,k-t)))===0,'old rank-one root polynomial identically zero');}
   for(let ww of witnesses){let rr=roots(evaluate(C,ww)).filter(z=>toyTag(z)===tag);
      must(rr.length===1&&rr[0]===k,'all witnesses recover under shear');}
   regression={seed,w,source_rank:rref(B2).rank,old_cofactor:cof,new_roots:r};
 }
 must(regression!==null,'cofactor-zero fixture found');
 return {run:695,purpose:'all-witness correctness of full-rank spectral release only',
    status:'finite algebra verified; no hiding, QPT extraction, or real signature verification',
    field:q,gates:m,width:n,key:k,setups:12,valid_recoveries:cases,
    forced_zero_cofactor:regression,assertions_passed:assertions};
})();
if(typeof console!=="undefined")console.log(JSON.stringify(report,null,2));
