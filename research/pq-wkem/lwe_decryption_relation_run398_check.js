() => {
 const q=97, m=4, B=1, half=48;
 let assertions=0;
 function ck(x,desc){assertions++;if(!x)throw Error("assertion "+assertions+": "+desc);}
 const ctr=t=>{t=((t%q)+q)%q;return t<=48?t:t-q;};
 const valid=(A,b,s)=>A.every((a,i)=>Math.abs(ctr(b[i]-a.reduce((v,z,j)=>v+z*s[j],0)))<=B);
 const encrypt=(A,b,bit,r)=>{
   const u=A[0].map((_,j)=>A.reduce((z,row,i)=>z+row[j]*r[i],0)%q);
   const v=(b.reduce((z,bi,i)=>z+bi*r[i],0)+half*bit)%q;
   return {u,v};
 };
 const decrypt=(s,c)=>Math.abs(ctr(c.v-c.u.reduce((v,ui,i)=>v+s[i]*ui,0)))<q/4?0:1;
 const A0=[[0],[0],[0],[0]], b0=[0,0,0,0];
 for(let s=0;s<q;s++)for(let bit=0;bit<=1;bit++)for(let mask=0;mask<16;mask++){
   const r=[0,1,2,3].map(i=>(mask>>i)&1);
   ck(valid(A0,b0,[s]),"multi-witness source");
   ck(decrypt([s],encrypt(A0,b0,bit,r))===bit,"all-witness same bit");
 }
 const A=[[12,29],[53,34],[72,19],[26,81]], secret=[5,9],err=[1,0,-1,1];
 const b=A.map((row,i)=>(row[0]*secret[0]+row[1]*secret[1]+err[i])%q);
 const good=[];
 for(let s0=0;s0<q;s0++)for(let s1=0;s1<q;s1++)if(valid(A,b,[s0,s1]))good.push([s0,s1]);
 ck(good.some(s=>s[0]===5&&s[1]===9),"honest source exists");
 for(const s of good)for(let bit=0;bit<=1;bit++)for(let mask=0;mask<16;mask++)ck(decrypt(s,encrypt(A,b,bit,[0,1,2,3].map(i=>(mask>>i)&1)))===bit,"honest source recovery");
 const badA=[[0,0],[0,0],[0,0],[0,0]],badB=[10,0,0,0];
 for(let s0=0;s0<q;s0++)for(let s1=0;s1<q;s1++)ck(!valid(badA,badB,[s0,s1]),"false instance no witness");
 let supports=[new Set(),new Set()];
 for(let bit=0;bit<=1;bit++)for(let mask=0;mask<16;mask++){
   const c=encrypt(badA,badB,bit,[0,1,2,3].map(i=>(mask>>i)&1));
   ck(c.u.every(x=>x===0),"zero first ciphertext component");
   supports[bit].add(c.v);
   ck((c.v===0||c.v===10?0:c.v===48||c.v===58?1:-1)===bit,"public decrypt false");
 }
 ck([...supports[0]].every(x=>!supports[1].has(x)),"false ciphertext supports disjoint");
 let count=0;
 for(let K=0;K<256;K++){
   let recovered=0;
   for(let j=0;j<8;j++){
     const r=[j&1,(j>>1)&1,(K+j)&1,(K>>j)&1];
     const ct=encrypt(badA,badB,(K>>j)&1,r);
     recovered|=(ct.v===0||ct.v===10?0:1)<<j;
   }
   ck(recovered===K,"full seed recovered with no source");
   count++;
 }
 return {run:398,status:"PASS",assertions,q,m,B,multi_witness_count:97,honestly_generated_witness_count:good.length,adversarial_false_witness_count:0,false_support_bit0:[...supports[0]].sort((a,b)=>a-b),false_support_bit1:[...supports[1]].sort((a,b)=>a-b),recovered_8bit_seeds:count,actual_LWE_security:false,all_false_instance_hiding:false,Syscoin_relation:false};
}
console.log(JSON.stringify(run398(), null, 2));
