const report = (function runCheck(){
 let seed=0x52533134, checks=0;
 function random32(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;}
 function rand(n){return random32()%n;}
 function ok(v,msg){checks++;if(!v)throw Error(msg);}
 const q=1099511627689,d=512,n=20680,B=16384,b=14,ell=512,h=3,caps=2;
 const g=Math.floor(q/2**b),u=Math.ceil(g/2),T=h*caps*Math.ceil(ell/b);
 const excess=n-d*Math.log2(q),variance=(n+1)*B*(B+1)/3;
 const bern=u*u/(2*(variance+B*u/3));
 const logTail=1-bern/Math.LN2,logAll=excess+Math.log2(T)+logTail;
 const oldMat=512*21008*5,oldCt=258*(21008+1)*5,newMat=512*n*5,newCt=T*(n+1)*5;
 ok(g===67108863&&T===222,"packing");
 ok(-excess< -190 &&logAll < -180,"statistical margin");
 ok(newCt<oldCt&&newMat<oldMat,"payload size");
 let totalHits=0;
 const vec=[[0,0],[0,1],[1,0],[1,1]];
 for(let a0=0;a0<3;a0++)for(let a1=0;a1<3;a1++)for(let t=0;t<3;t++)for(const w of vec)
   totalHits+=Number((a0*w[0]+a1*w[1]-t+9)%3===0);
 ok(totalHits===36,"exact finite expectation");
 for(let i=0;i<4;i++)for(let j=i+1;j<4;j++){
   let both=0;
   for(let a0=0;a0<3;a0++)for(let a1=0;a1<3;a1++)for(let t=0;t<3;t++){
     const v=vec[i],w=vec[j];
     both+=Number((a0*v[0]+a1*v[1]-t+9)%3===0&&(a0*w[0]+a1*w[1]-t+9)%3===0);
   }
   ok(both===3,"exact pairwise independence");
 }
 const toyq=257,toyn=12,toyB=2,toyb=3,toyg=32,maskMax=1<<toyn;
 function pack(v){const a=[];for(let j=0;j<v.length;j+=toyb){let z=0;for(let k=0;k<toyb&&j+k<v.length;k++)z|=v[j+k]<<k;a.push(z);}return a;}
 function unpack(a){let v=[];for(const z of a)for(let k=0;k<toyb;k++)v.push((z>>k)&1);return v.slice(0,16);}
 function decode(x){let z=(x%toyq+toyq)%toyq;const v=Math.floor((z+Math.floor(toyg/2))/toyg);return v>=1<<toyb?0:v;}
 let trials=40,trueCount=0,multi=0,good=0,wchecks=0,mismatch=0;
 for(let trial=0;trial<trials;trial++){
   const A=Array.from({length:toyn},()=>rand(toyq)),t=rand(toyq),valid=[];
   for(let w=0;w<maskMax;w++){let z=0;for(let i=0;i<toyn;i++)if(w&(1<<i))z+=A[i];if(z%toyq===t)valid.push(w);}
   if(!valid.length)continue;
   trueCount++;if(valid.length>1)multi++;
   const K=Array.from({length:16},()=>rand(2)),a=Array.from({length:16},()=>rand(2)),c=Array.from({length:16},()=>rand(2));
   const shares=[a,c,K.map((bit,i)=>bit^a[i]^c[i])];
   let allGood=true;
   for(let capsule=0;capsule<2;capsule++){
     const byW=new Map(valid.map(w=>[w,[[],[],[]]]));
     for(let lane=0;lane<3;lane++)for(const m of pack(shares[lane])){
       const secret=rand(toyq),errors=Array.from({length:toyn},()=>rand(2*toyB+1)-toyB),ep=rand(2*toyB+1)-toyB;
       const beta=A.map((x,i)=>(x*secret+errors[i]+toyq*toyq)%toyq);
       const tau=((t*secret+ep+toyg*m)%toyq+toyq)%toyq;
       for(const w of valid){
         let bs=0,es=0;
         for(let i=0;i<toyn;i++)if(w&(1<<i)){bs+=beta[i];es+=errors[i];}
         const residual=((tau-bs)%toyq+toyq)%toyq;
         const expected=((toyg*m+ep-es)%toyq+toyq)%toyq;
         ok(residual===expected,"ordinary LWE witness residual");
         byW.get(w)[lane].push(decode(residual));
       }
     }
     for(const w of valid){
       const decoded=byW.get(w).map(unpack),recovered=K.map((_,i)=>decoded[0][i]^decoded[1][i]^decoded[2][i]);
       wchecks++;
       if(recovered.some((bit,i)=>bit!==K[i])){mismatch++;allGood=false;}
     }
   }
   if(allGood)good++;
 }
 ok(trueCount>=30&&multi>=30&&wchecks>200&&good>0,"nontrivial toy all-witness tests");
 for(let m=0;m<8;m++){const secret=rand(toyq),beta=secret%toyq,tau=(3*secret+toyg*m)%toyq;ok(decode(((tau-3*beta)%toyq+toyq)%toyq)===m,"FALSE nonbinary opener");}
 return {checkpoint:"RS14-20261031",status:"restricted random-source efficiency only, not generic NP witness-KEM",assertions:checks,seed:"0x52533134",params:{q,d,n,B,b,ell,h,caps,T,g,u},bounds_log2:{false_upper:Number((-excess).toFixed(6)),single_w_tail:Number(logTail.toFixed(6)),all_w_all_blocks:Number(logAll.toFixed(6))},storage:{old_matrix:oldMat,old_ciphertext:oldCt,new_matrix:newMat,new_ciphertext:newCt,ciphertext_savings_pct:Number((100*(1-newCt/oldCt)).toFixed(6))},toy:{trials,true_sources:trueCount,multiple_witness_sources:multi,all_witness_correct_trials:good,witness_capsule_checks:wchecks,mismatches:mismatch},known_false_attack:"A=[1],t=[3],nonbinary z=3 cancels secret; generic ORIGINAL soundness is not obtained"};
})();
console.log(JSON.stringify(report,null,2));
