(function run545Check(){
 const occupancy=[],grover=[];let assertions=0;
 for(const [N,m] of [[4,1],[4,2],[4,4],[4,8],[8,1],[8,2],[8,4]]){
  const count=N**m;let sum=0;
  for(let x=0;x<count;x++){
   let z=x;const seen=new Set();
   for(let j=0;j<m;j++){seen.add(z%N);z=Math.floor(z/N)}
   sum+=seen.size/N;
  }
  const mean=sum/count,law=1-(1-1/N)**m;
  if(Math.abs(mean-law)>1e-12)throw Error("occupancy mismatch");
  assertions++;
  occupancy.push({N,m,mean:Number(mean.toFixed(10)),law:Number(law.toFixed(10))});
 }
 for(const b of [5,7,9]){
  const N=2**b;
  for(const t of [1,2,4,8]){
   const active=new Set(Array.from({length:t},(_,j)=>(j*13+7)%N));
   if(active.size!==t)throw Error("not distinct");
   const theta=Math.asin(Math.sqrt(t/N));
   const rounds=Math.max(0,Math.round(Math.PI/(4*theta)-.5));
   let a=Array(N).fill(1/Math.sqrt(N));
   for(let j=0;j<rounds;j++){
    for(const i of active)a[i]=-a[i];
    const avg=a.reduce((x,y)=>x+y,0)/N;
    a=a.map(v=>2*avg-v);
   }
   const observed=[...active].reduce((x,i)=>x+a[i]**2,0);
   const predicted=Math.sin((2*rounds+1)*theta)**2;
   if(Math.abs(observed-predicted)>1e-10)throw Error("Grover mismatch");
   if(Math.abs(a.reduce((x,v)=>x+v*v,0)-1)>1e-10)throw Error("norm mismatch");
   assertions+=2;
   grover.push({b,t,q:rounds,p:Number(observed.toFixed(10))});
  }
 }
 return {run:545,assertions,occupancy,grover,passed:true,scope:"exact small occupancy and coherent search identities, no WKEM"};
})();
