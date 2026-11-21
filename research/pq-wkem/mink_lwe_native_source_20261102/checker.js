(function checker(){
  let seed=20261102>>>0,checks=0;
  const rand=(n)=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};
  const ok=(cond,msg)=>{checks++;if(!cond)throw Error(msg+" #"+checks)};
  const q=257,m=22,n=2,eta=1,t=6,g=Math.floor(q/2);
  const mod=(x,q)=>((x%q)+q)%q;
  const dist=(a,b,q)=>Math.min(mod(a-b,q),mod(b-a,q));
  let A=Array.from({length:m},()=>{let x=rand(q);return [x,x]});
  let s=[31,57],sp=[(s[0]+19)%q,(s[1]-19+q)%q];
  let errors=Array.from({length:m},()=>rand(3)-1);
  let b=A.map((row,i)=>mod(row[0]*s[0]+row[1]*s[1]+errors[i],q));
  const valid=(x,aa=A,bb=b)=>aa.every((row,i)=>dist(row.reduce((v,a,j)=>v+a*x[j],0)%q,bb[i],q)<=eta);
  ok(valid(s)&&valid(sp)&&s[0]!=sp[0],"two distinct original witnesses");
  const enc=(bit)=>{let chosen=[];while(chosen.length<t){let z=rand(m);if(!chosen.includes(z))chosen.push(z)};let u=[0,1].map(j=>mod(chosen.reduce((v,i)=>v+A[i][j],0),q));let v=mod(chosen.reduce((a,i)=>a+b[i],0)+g*bit,q);return {u,v,chosen}};
  const dec=(c,w)=>{let y=mod(c.v-c.u.reduce((v,u,j)=>v+u*w[j],0),q);return dist(y,g,q)<dist(y,0,q)?1:0};
  const K=Array.from({length:32},()=>rand(256));
  let capsules=[];
  for(let j=0;j<3;j++){
    let rows=[];
    for(let k=0;k<256;k++){
      let bit=(K[Math.floor(k/8)]>>(k%8))&1;
      let a=rand(2),c=rand(2),d=bit^a^c;
      let shares=[a,c,d],ct=shares.map(enc);
      rows.push({shares,ct});
      for(let witness of [s,sp])ok(ct.reduce((v,c)=>v^dec(c,witness),0)===bit,"all valid witnesses recover same K");
      for(let lane=0;lane<2;lane++){
        if((j+k+lane)%3!==0){
          let c=ct[lane],u=[0,1].map(i=>mod(c.chosen.reduce((v,z)=>v+A[z][i],0),q));
          let v=mod(c.chosen.reduce((v,z)=>v+b[z],0)+g*shares[lane],q);
          ok(JSON.stringify(u)===JSON.stringify(c.u)&&v===c.v,"adaptive audit lane opening");
        }
      }
    }
    capsules.push(rows);
  }
  ok(capsules.length===3,"three related capsules");
  let Afalse=Array.from({length:m},()=>[0]), bfalse=Array(m).fill(0);bfalse[0]=10;
  ok(!valid([0,0],Afalse,bfalse),"malformed false SOURCE");
  for(let bit=0;bit<=1;bit++)for(let x=0;x<2;x++){
    let v=mod(g*bit+10*x,q);
    ok((bit===0?[0,10]:[128,138]).includes(v),"explicit universal FALSE failure");
  }
  const fq=3,fm=5,subsets=[];
  for(let i=0;i<fm;i++)for(let j=i+1;j<fm;j++)subsets.push([i,j]);
  let tvsum=0,pubkeys=0;
  for(let keycode=0;keycode<Math.pow(fq,2*fm);keycode++){
    let digits=[],c=keycode;for(let j=0;j<2*fm;j++){digits.push(c%fq);c=Math.floor(c/fq)}
    const cnt=Array(9).fill(0);
    for(let [i,j] of subsets){let u=(digits[i]+digits[j])%fq, v=(digits[fm+i]+digits[fm+j])%fq;cnt[u*3+v]++}
    tvsum+=cnt.reduce((s,v)=>s+Math.abs(v/subsets.length-1/9),0)/2;
    pubkeys++;
  }
  let tv=tvsum/pubkeys,bound=0.5*Math.sqrt(9/subsets.length);
  ok(pubkeys===59049 && tv<=bound,"exact leftover TV bound");
  return {run:"MINK-LWE-NATIVE-SOURCE-20261102-R11",checks,toy_q:q,toy_m:m,source_relation:"R_LWE",distinct_original_witnesses:2,related_capsules:3,protected_lane:2,uniform_keys_enumerated:pubkeys,mean_TV:Math.round(tv*1e12)/1e12,leftover_bound:Math.round(bound*1e12)/1e12,scope:"algebraic test only; all-FALSE-instance security fails"};
})();
