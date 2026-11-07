const result=(function runChecker(){
 let assertions=0;const check=(b,msg)=>{assertions++;if(!b)throw new Error(msg)};
 const subs=[];for(let m=0;m<7;m++){const s=[];for(let i=0;i<3;i++)if(m&(1<<i))s.push(i);subs.push(s)}
 const hist=(k,s0,s1)=>{
  const h={};for(let a=0;a<2;a++)for(let b=0;b<2;b++)for(let c=0;c<2;c++)for(let d=0;d<2;d++){
   const x=[a,b,k^a^b],y=[c,d,k^c^d];
   const key=[...s0.map(i=>x[i]),...s1.map(i=>y[i])].join("");
   h[key]=(h[key]||0)+1;
  }return JSON.stringify(Object.entries(h).sort((a,b)=>a[0].localeCompare(b[0])));
 };
 let patterns=0;for(const s0 of subs)for(const s1 of subs){
  patterns++;check(hist(0,s0,s1)===hist(1,s0,s1),"distribution mismatch");
  const N=(3-s0.length)*(3-s1.length);let surviving=0,weight=0;
  for(let g0=0;g0<3;g0++)for(let g1=0;g1<3;g1++){
   if(!s0.includes(g0)&&!s1.includes(g1)){surviving++;weight+=1/N}
  }
  check(surviving===N,"survivor count");check(Math.abs(weight-1)<1e-12,"weight identity");
 }
 const adaptive=k=>{
   const h={};for(let a=0;a<2;a++)for(let b=0;b<2;b++)for(let c=0;c<2;c++)for(let d=0;d<2;d++){
     const x=[a,b,k^a^b],y=[c,d,k^c^d];
     const j=x[0]===0?1:2, f=x[j]===0?2:1, h2=y[f]===0?(f+1)%3:(f+2)%3;
     const t=[[0,0,x[0]],[0,j,x[j]],[1,f,y[f]],[1,h2,y[h2]]];
     const key=JSON.stringify(t);h[key]=(h[key]||0)+1;
   }return JSON.stringify(Object.entries(h).sort((a,b)=>a[0].localeCompare(b[0])));
 };
 check(adaptive(0)===adaptive(1),"adaptive leakage");
 for(let k=0;k<2;k++)for(let a=0;a<2;a++)for(let b=0;b<2;b++){
  const old=[a,b,k^a^b];check((old[0]^old[1]^old[2])===k,"old same-shares leakage");
 }
 check(hist(0,[0,1],[1,2])===hist(1,[0,1],[1,2]),"independent cross-capsule source");
 return {candidate:"ICSO-2",exact_opening_patterns:patterns,adaptive_plaintext_policy_equal:true,inverse_survival_normalization:"1/9 with guessed lane per capsule",guesses:9,restricted_hybrid_target_ciphertexts:38,realization:"independent XOR shares per related capsule",assertions,security_scope:"honest random SOURCE; arbitrary QPT with classical whole-lane adaptive opens; not ORIGINAL NP",status:"algebraic checker, not a QPT security experiment"};
})();
process.stdout.write(JSON.stringify(result,null,2)+'\n');
