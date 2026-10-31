// Run701 compact, deterministic exact algebra fixture. NOT a cryptographic test.
const crypto=require('crypto');
const q=101,K=17;let assertions=0;
const mod=x=>(x%q+q)%q,ok=(a,s)=>{if(!a)throw Error(s);assertions++};
function rank(A){let B=A.map(x=>x.map(mod)),h=B.length,w=B[0].length,r=0;const ip=x=>{let a=1;for(let i=0;i<q-2;i++)a=mod(a*x);return a};for(let j=0;j<w&&r<h;j++){let t=r;while(t<h&&!B[t][j])t++;if(t===h)continue;[B[r],B[t]]=[B[t],B[r]];let k=ip(B[r][j]);B[r]=B[r].map(v=>mod(v*k));for(let i=r+1;i<h;i++){const a=B[i][j];if(a)B[i]=B[i].map((v,l)=>mod(v-a*B[r][l]))}r++}return r}
function compile(nv,clauses){const p=1+nv+2*clauses.length,m=nv+3*clauses.length;
 const lit=(l,z)=>l>0?z[l]:mod(z[0]-z[-l]);const g=[];
 for(let i=1;i<=nv;i++)g.push(z=>[z[i],z[i],z[i],z[0]]);
 clauses.forEach((cl,j)=>{const i=1+nv+2*j,k=i+1;
 g.push(z=>[lit(cl[0],z),lit(cl[1],z),mod(lit(cl[0],z)+lit(cl[1],z)-z[i]),z[0]]);
 g.push(z=>[z[i],lit(cl[2],z),mod(z[i]+lit(cl[2],z)-z[k]),z[0]]);
 g.push(z=>[mod(z[k]-z[0]),z[0],0,z[0]])});
 const lift=w=>{const z=[1,...w];clauses.forEach(cl=>{const v=cl.map(l=>l>0?w[l-1]:1-w[-l-1]);z.push(+(!!(v[0]||v[1])),+(!!(v[0]||v[1]||v[2])))});return z};
 const valid=z=>z[0]===1&&g.every(f=>{const [a,b,c,d]=f(z);return mod(a*b-c*d)===0});
 const original=w=>clauses.every(cl=>cl.some(l=>l>0?w[l-1]:1-w[-l-1]));
 return {g,lift,valid,original,nv,p,m,clauses}}
function matrixGate(t,x){const [a,b,c,d]=t;return [[a,c,mod(-x),0],[d,b,0,x],[0,0,b,c],[0,0,d,a]].map(row=>row.map(mod))}
function run(nv,clauses,seed){let state=seed;const rnd=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state%q};const c=compile(nv,clauses),N=2*c.m+1;
 const factors=c.g.map(()=>({L:Array.from({length:N},()=>Array.from({length:4},rnd)),R:Array.from({length:4},()=>Array.from({length:N},rnd)),X:Array.from({length:c.p},rnd)}));
 const M=z=>{const out=Array.from({length:N},()=>Array(N).fill(0));c.g.forEach((f,i)=>{const {L,R,X}=factors[i],t=f(z),x=mod(X.reduce((s,v,j)=>s+v*z[j],0)),G=matrixGate(t,x);for(let a=0;a<N;a++)for(let b=0;b<N;b++)for(let u=0;u<4;u++)for(let v=0;v<4;v++)if(G[u][v])out[a][b]=mod(out[a][b]+L[a][u]*G[u][v]*R[v][b])});return out};
 const Cs=Array.from({length:c.p},(_,j)=>M(Array.from({length:c.p},(_,k)=>+(k===j))));for(let a=0;a<N;a++)Cs[0][a][a]=mod(Cs[0][a][a]+K);
 const publicC=z=>Array.from({length:N},(_,a)=>Array.from({length:N},(_,b)=>mod(Cs.reduce((s,C,j)=>s+C[a][b]*z[j],0))));
 const pk=crypto.createHash('sha256').update('toy-native:' +seed+':'+K).digest('hex');let satisfying=0,invalid=0,recovered=0,different=new Set();
 for(let mask=0;mask<(1<<nv);mask++){const w=Array.from({length:nv},(_,i)=>(mask>>i)&1),z=c.lift(w),yes=c.original(w);ok(c.valid(z)===yes,'SOURCE iff ORIGINAL');for(const f of c.g){const t=f(z),G=matrixGate(t,23);ok(rank(G)===(mod(t[0]*t[1]-t[2]*t[3])===0?2:4),'gate rank iff R1CS')}
 const C=publicC(z),D=M(z);for(let a=0;a<N;a++)for(let b=0;b<N;b++)ok(mod(C[a][b]-(a===b?K:0))===D[a][b],'public full-matrix equality');
 if(yes){satisfying++;ok(rank(D)<N,'common eigenvalue for valid SOURCE');different.add(JSON.stringify(C));let selected=[];for(let k=0;k<q;k++){const P=C.map((row,a)=>row.map((x,b)=>mod(x-(a===b?k:0))));if(rank(P)<N&&crypto.createHash('sha256').update('toy-native:'+seed+':'+k).digest('hex')===pk)selected.push(k)}ok(selected.length===1&&selected[0]===K,'same native test key recovered');recovered++}else{invalid++;ok(!c.valid(z),'invalid rejected');ok(rank(D)===N,'fixed-invalid sampled full rank')} }
 if(satisfying>1)ok(different.size===satisfying,'witness-dependent states remain distinct');return {variables:nv,clauses:clauses.length,gates:c.m,source_coordinates:c.p,matrix_size:N,valid_original_witnesses:satisfying,invalid_original_assignments:invalid,common_key_recoveries:recovered,distinct_valid_matrices:different.size}}
const pos=run(2,[[1,2,1]],70131),neg=run(1,[[1,1,1],[-1,-1,-1]],70132);ok(pos.common_key_recoveries===3&&neg.common_key_recoveries===0,'true false fixtures');console.log(JSON.stringify({run:701,scope:'3CNF SOURCE -> typed spectral public operator -> same capability; algebra only',q,positive:pos,negative:neg,assertions,security:'QPT hiding/arbitrary extraction UNPROVED'},null,2));
