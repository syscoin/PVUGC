return (()=>{let checks=0,fixtures=0,recovered=0,seed=40720261010>>>0;
const ok=(v)=>{checks++;if(!v)throw Error("fail "+checks)};
const rnd=(q)=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%q};
const mod=(x,q)=>((x%q)+q)%q;
const dot=(a,b,q)=>mod(a.reduce((s,v,i)=>s+v*b[i],0),q);
const inv=(a,q)=>{let t=1,b=mod(a,q),e=q-2;while(e){if(e%2)t=mod(t*b,q);b=mod(b*b,q);e=Math.floor(e/2)}return t};
for(const q of [17,257,65537])for(const n of [2,3,4])for(let z=0;z<100;z++){
const k=8,t=[1,-1,1,-1,0,1,-1,0];
const S=Array.from({length:k},()=>Array.from({length:n},()=>rnd(q)));
const v=Array.from({length:n},()=>rnd(q)),g=Array.from({length:k},()=>rnd(q));
if(dot(t,g,q)===0)g[0]=mod(g[0]+1,q);
const tg=dot(t,g,q);ok(tg!==0);
const a=Array.from({length:n},(_,j)=>mod(t.reduce((s,x,i)=>s+x*S[i][j],0),q));
const makeMask=()=>{let M=Array.from({length:k},()=>Array.from({length:n},()=>rnd(q)));
for(let j=0;j<n;j++){M[0][j]=0;M[0][j]=mod(-M.reduce((s,row,i)=>s+t[i]*row[j],0),q)}
ok(Array.from({length:n},(_,j)=>dot(t,M.map(row=>row[j]),q)).every(x=>x===0));return M};
for(let gate=0;gate<3;gate++){
 const B=Array.from({length:n},()=>Array.from({length:n},()=>rnd(q)));
 const obs=[];
 for(let b=0;b<2;b++){
  const M=makeMask();
  const C=Array.from({length:k},(_,i)=>Array.from({length:n},(_,j)=>mod(
   S[i].reduce((s,x,r)=>s+x*(B[r][j]-(b&&r===j?r+1:0)),0)+M[i][j],q)));
  const u=Array.from({length:n},(_,j)=>dot(t,C.map(row=>row[j]),q));
  const ideal=Array.from({length:n},(_,j)=>mod(a.reduce((s,x,r)=>s+x*(B[r][j]-(b&&r===j?r+1:0)),0),q));
  ok(u.every((x,j)=>x===ideal[j]));obs.push(u);
 }
 const a2=obs[0].map((x,j)=>mod((x-obs[1][j])*inv(j+1,q),q));
 ok(a2.every((x,j)=>x===a[j]));
}
for(let mu=0;mu<2;mu++){
 const noise=Array.from({length:k},()=>rnd(q));
 noise[0]=0;noise[0]=mod(-dot(t,noise,q),q);
 const C3=Array.from({length:k},(_,i)=>mod(dot(S[i],v,q)+g[i]*mu+noise[i],q));
 const y=dot(t,C3,q);
 const got=mod((y-dot(a,v,q))*inv(tg,q),q);
 ok(got===mu);recovered++;
}
fixtures++;
}
return {run:407,status:"PASS",assertions:checks,fixtures,recovered_without_witness:recovered,prime_fields:[17,257,65537],dimensions:[2,3,4],scope:"Noiseless modular algebra with adversary-supplied common left-kernel mask. Not CLW lattice TrapGen, LWE, QROM, or PQ signature benchmark"};})();
