"use strict";
// Exact executed R115 finite checker; Node 16+ / BigInt, no external modules.
const check = function check(){
 const Q=65521n,d=256,m=2000,ell=64,L=3929,S=7856*8;
 let n=0,dist=0,cases=0,qual=0;
 const ok=(v)=>{n++;if(!v)throw Error("R115 offline checker failed assertion "+n);};
 ok(Q**BigInt(L)>=2n**BigInt(S));ok(Q**BigInt(L-1)<2n**BigInt(S));
 ok(2*m>=L);ok(3*2729<8190);ok(2*(d*16+m*3)===20192);
 ok(Math.ceil(20192/(2*ell))*(d+ell)*2===101120);
 ok(Math.ceil(S/(2*ell))*(d+ell)*2===314240);
 ok(2*L===7858);ok(9*101120+2*L===917938);
 let x=(1n<<62847n)+115n,z=x,ds=[];
 for(let i=0;i<L;i++){ds.push(z%Q);z/=Q;}ok(z===0n);
 z=0n;for(let i=L-1;i>=0;i--)z=z*Q+ds[i];ok(z===x);
 const cl=[["H1","H2"],["H2","H3"],["H3","H4"],["M","H1","H4"]],who=["H1","H2","H3","H4","M"];
 for(let mask=0;mask<32;mask++){
   const s=new Set(who.filter((_,i)=>mask&(1<<i)));
   const allowed=cl.every(c=>c.some(x=>s.has(x)));
   for(let t=0;t<16;t++){
     const a=(mask+t*3+3)&15,b=(mask*7+t+2)&15,c=(mask+t*11+9)&15,shares=[a,b,c,t^a^b^c];
     if(allowed){ok(cl.every(c=>c.some(x=>s.has(x))));ok(shares.reduce((p,v)=>p^v,0)===t);qual++;}
     else ok(cl.some(c=>!c.some(x=>s.has(x))));
     cases++;
   }
 }
 function pub(arr,pad){
   let j=pad+3;for(let i=0;i<arr.length;i++)j=(j*37+arr[i]*(i+5)+13)%1009;
   const ck=(j*101+pad*17+7)%1009,aux=(ck*67+j*19+pad)%1009;
   return [...arr,pad,j,ck,aux,"sibling-context"].join(":");
 }
 for(let cut=0;cut<4;cut++){
   let first=null;
   for(let t=0;t<4;t++)for(let sig=0;sig<4;sig++){
     const hist=new Map();
     for(let a=0;a<4;a++)for(let b=0;b<4;b++)for(let c=0;c<4;c++)for(let pad=0;pad<4;pad++){
       const visible=[a,b,c,t^a^b^c].filter((_,i)=>i!==cut);
       const key=pub(visible,(sig+pad)%4);
       hist.set(key,(hist.get(key)||0)+1);dist++;
     }
     ok(hist.size===256&&[...hist.values()].every(k=>k===1));
     if(first)ok([...first].every(([k,v])=>hist.get(k)===v));else first=hist;
   }
 }
 return {run:"R115-LWE-OUTPUT-NATIVE-PAD-20261106",result:"PASS",assertions:n,
  exactFinalHybridCases:dist,restrictedPolicyCases:cases,qualifiedPolicyCases:qual,
  params:{q:Number(Q),d,m,ell,signatureBytes:7856,seedBits:20192,groupsPerOccurrence:158,
    newBytesPerOccurrence:101120,oldBytesPerOccurrence:314240,
    oneMaskedNativeSignatureBytes:7858,nineOccurrencesNewBytes:917938,nineOccurrencesOldBytes:2828160},
  limits:"Finite algebra/toy full joint distribution, NOT quantum security or generic ORIGINAL NP"};
};
console.log(JSON.stringify(check(),null,2));
