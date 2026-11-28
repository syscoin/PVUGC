function groupChecker(){
const P=2039,Q=1019,G=4,inv4=255;let checks=0,rows=0,honest=0,attacks=0;
const ck=(x,msg)=>{checks++;if(!x)throw Error("assert "+checks+" "+msg)};
const mod=(x,m)=>((x%m)+m)%m;
const pow=(base,exp)=>{let v=1,b=mod(base,P),e=exp;while(e>0){if(e%2)v=v*b%P;b=b*b%P;e=Math.floor(e/2)}return v};
const product=(U,z)=>{let t=1;for(let i=0;i<U.length;i++)if(z[i])t=t*pow(U[i],z[i])%P;return t};
let state=57721;const rand=n=>{state^=state<<13;state^=state>>>17;state^=state<<5;return (state>>>0)%n};
const cases=[
{label:"false contradiction",n:1,clauses:[[[0,1],[0,1],[0,1]],[[0,0],[0,0],[0,0]]]},
{label:"true multiple witnesses",n:2,clauses:[[[0,1],[1,1],[0,1]]]}
];
for(const f of cases){
const n=f.n,m=f.clauses.length,N=2*n+7*m,A=[],b=[];
for(let i=0;i<n;i++){const v=Array(N).fill(0);v[2*i]=v[2*i+1]=1;A.push(v);b.push(1)}
for(let j=0;j<m;j++){
 let v=Array(N).fill(0);for(let pat=1;pat<=7;pat++)v[2*n+7*j+pat-1]=1;A.push(v);b.push(1);
 for(let k=0;k<3;k++){let row=Array(N).fill(0);for(let pat=1;pat<=7;pat++)if((pat>>k)&1)row[2*n+7*j+pat-1]=1;const [i,pol]=f.clauses[j][k];row[2*i+pol]-=1;A.push(row);b.push(0)}
}
const dot=(u,v)=>u.reduce((t,x,i)=>t+x*v[i],0);
const y=Array(N).fill(0);for(let i=0;i<n;i++)y[2*i]=y[2*i+1]=2;
for(let j=0;j<m;j++)for(const pat of [1,2,4,7])y[2*n+7*j+pat-1]=1;
for(let i=0;i<A.length;i++){ck(dot(A[i],y)===4*b[i],"public scaled row");rows++}
const ws=[];
for(let mask=0;mask<2**n;mask++){
 const w=Array.from({length:n},(_,i)=>(mask>>i)&1);
 if(!f.clauses.every(cl=>cl.some(([i,pol])=>w[i]===pol)))continue;
 const z=Array(N).fill(0);for(let i=0;i<n;i++)z[2*i+w[i]]=1;
 for(let j=0;j<m;j++){let pat=0;for(let k=0;k<3;k++){const [i,pol]=f.clauses[j][k];if(w[i]===pol)pat|=(1<<k)}z[2*n+7*j+pat-1]=1}
 for(let i=0;i<A.length;i++)ck(dot(A[i],z)===b[i],"real witness row");
 ws.push(z)
}
if(f.label.startsWith("false"))ck(ws.length===0,"false formula");else ck(ws.length>=2,"multi witness");
const B=n+m;
for(let trial=0;trial<64;trial++){
 const r=Array.from({length:A.length},()=>rand(Q)),e=Array.from({length:N},()=>rand(3)-1),e0=rand(3)-1;
 const C=Array.from({length:N},(_,i)=>mod(A.reduce((s,row,j)=>s+row[i]*r[j],0)+e[i],Q));
 const t=mod(dot(b,r)+e0,Q),target=pow(G,t),U=C.map(u=>pow(G,u));
 for(const z of ws){
 const V=product(U,z),limit=B+1;let found=false;
 for(let eta=-limit;eta<=limit;eta++)if(V*pow(G,mod(eta,Q))%P===target)found=true;
 ck(found,"honest can reconstruct same target");honest++;
 }
 const V=product(U,y),lim=4*(B+1),d=4*e0-dot(y,e);
 ck(Math.abs(d)<=lim,"noise bound");
 ck(V*pow(G,mod(d,Q))%P===pow(target,4),"group scale identity");
 let recovered=false;
 for(let eta=-lim;eta<=lim;eta++){
 const W=pow(V*pow(G,mod(eta,Q))%P,inv4);
 if(W===target)recovered=true;
 }
 ck(recovered,"public fractional group opening");attacks++
}
}
return {checks,public_row_checks:rows,honest_witness_group_openings:honest,public_fractional_group_recoveries:attacks,group:{P,Q,G,inv4},scope:"Finite exact group identities; NOT SHA or QPT hardness"};
}
console.log(JSON.stringify(groupChecker(),null,2));
