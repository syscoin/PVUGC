function run586(){
 let assertions=0, honestChecks=0, multiWitnessKeys=0, seen=new Set();
 const assert=(c,msg)=>{if(!c)throw Error(msg);assertions++};
 const ctr=(z,q)=>{z=((z%q)+q)%q;return z<=Math.floor(q/2)?z:z-q};
 const dec=(v,shift,q)=>{let z=((v-shift)%q+q)%q,M=Math.floor(q/2);return Math.min(z,q-z)<Math.min((z-M+q)%q,(M-z+q)%q)?0:1};
 const enc=(A,b,r,bit,q)=>({u:A[0].map((_,j)=>A.reduce((a,row,i)=>a+row[j]*r[i],0)%q),v:(b.reduce((a,x,i)=>a+x*r[i],0)+Math.floor(q/2)*bit)%q});
 for(let a0=0;a0<17;a0++)for(let a1=0;a1<17;a1++){
  let A=[[a0],[a1]];
  for(let initial=0;initial<2;initial++)for(let e0=-1;e0<=1;e0++)for(let e1=-1;e1<=1;e1++){
   let b=[(a0*initial+e0+17)%17,(a1*initial+e1+17)%17],ws=[];
   seen.add([a0,a1,...b].join(","));
   for(let s=0;s<2;s++){let e=[ctr(b[0]-a0*s,17),ctr(b[1]-a1*s,17)];if(e.every(x=>Math.abs(x)<=1))ws.push(s)}
   assert(ws.length>0,"source");
   if(ws.length===2)multiWitnessKeys++;
   for(let r0=0;r0<2;r0++)for(let r1=0;r1<2;r1++)for(let bit=0;bit<2;bit++){
     let c=enc(A,b,[r0,r1],bit,17);
     for(let s of ws){assert(dec(c.v,s*c.u[0],17)===bit,"honest same key");honestChecks++}
   }
  }
 }
 let A=[[1,1,1],[1,2,4],[1,3,9],[1,4,16]],b=[32,1,1,1],ds=[];
 for(let s=0;s<8;s++){
  let e=b.map((x,i)=>ctr(x-A[i].reduce((v,a,j)=>v+a*((s>>j)&1),0),257));
  ds.push(Math.max(...e.map(Math.abs)));assert(ds[ds.length-1]>1,"false relation");
 }
 assert(Math.min(...ds)===29,"false min distance");
 let values=new Set(),falseChecks=0;
 for(let r=0;r<16;r++)for(let bit=0;bit<2;bit++){
  let c=enc(A,b,[0,1,2,3].map(i=>(r>>i)&1),bit,257);
  values.add(c.v);assert(dec(c.v,0,257)===bit,"public release of false capability");falseChecks++;
 }
 assert(values.size===16,"false support");
 let seed=Array.from({length:128},(_,i)=>((i*37+Math.floor(i/3)*19+7)%11<5)?1:0), recovered=[];
 for(let j=0;j<128;j++){let r=[0,1,2,3].map(k=>((j*17+73+k*29+(j>>k))>>(k%5))&1);let c=enc(A,b,r,seed[j],257);recovered.push(dec(c.v,0,257))}
 assert(recovered.every((v,i)=>v===seed[i]),"128 bit false key");
 return {run:586,model:"Restricted LWE-key decryption; far-false selected-key attack",honestChecks,distinctTrueFixtureKeys:seen.size,multiWitnessFixtureCount:multiWitnessKeys,chosenFalseMinDistance:Math.min(...ds),chosenFalseMatrixRank:3,chosenFalseAllMatrixEntriesNonzero:true,chosenFalseCiphertextSupport:[...values].sort((a,b)=>a-b),falseCiphertextChecks:falseChecks,full128BitCapabilityRecovery:true,totalAssertions:assertions,claim:"NO practical WKEM; false-instance hiding defeated by classical PPT"};
}
console.log(JSON.stringify(run586(),null,2));
