console.log(JSON.stringify((function R78Checker() {
  let assertions=0,pointwise=0,adaptive=0,trueOpenings=0;
  const ok=(v,s)=>{assertions++;if(!v)throw Error("R78 assertion "+assertions+": "+s);};
  const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  const Q=4096,P=256,DELTA=1024,T=3072;
  const A1=[-1,4,4],A2=[-1,8,8],A3=[-1,12,12];
  const mod=(a,q)=>(a%q+q)%q;
  const source=(A,z,e,mu,q,p,delta)=>A.map((a,i)=>Math.floor((mod(a*z+e[i]+(i===0?delta*mu:0),q)+q/p/2)/(q/p))%p);
  const keyblind=(A,z,e,q,p)=>source(A,z,e,0,q,p,0);
  const cert=(A,t,q,d)=>A.every((a,i)=>mod(a*t,q)===(i===0?d:0));
  ok([A1,A2,A3].every(A=>cert(A,T,Q,DELTA)),"all share one shift");
  for(const c of [4,8,12])for(const a of [0,1])for(const b of [0,1])ok(c*(a+b)!==1,"binary original FALSE");
  for(let mu=0;mu<4;mu++)for(let z=0;z<Q;z++)for(let e=-1;e<=1;e++)for(const A of [A1,A2,A3]) {
    ok(eq(source(A,z,[e,-e,e],mu,Q,P,DELTA),keyblind(A,mod(z+mu*T,Q),[e,-e,e],Q,P)),"same source bytes");
    pointwise++;
  }
  let seed=0x781104;
  const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
  const signed=()=>random()%3-1;
  for(let i=0;i<512;i++){
    const mu=random()%4,z=random()%Q,zs=mod(z+mu*T,Q);
    const e=[signed(),signed(),signed()];
    const c1=source(A1,z,e,mu,Q,P,DELTA),s1=keyblind(A1,zs,e,Q,P);
    ok(eq(c1,s1),"adaptive prefix");
    const choice=(c1[0]%2===0)?A2:A3;
    const e2=[signed(),signed(),signed()];
    const c2=source(choice,z,e2,mu,Q,P,DELTA),s2=keyblind(choice,zs,e2,Q,P);
    ok(eq(c2,s2),"adaptive sibling");
    const U="toy-U-"+mu+"-"+i;
    const scope="original-claim|utxo:0|branch:challenge|anchors:window|t:3072";
    const view=(a,b)=>{const CK="CK|"+U+"|"+scope+"|"+JSON.stringify([a,b]);const AUX="AUX|"+U+"|"+CK;return [scope,a,b,CK,AUX,"adversarial-"+CK+"-"+AUX];};
    ok(eq(view(c1,c2),view(s1,s2)),"CK/Aux/adaptive joint view");
    adaptive++;
  }
  const q=32,p=16,d=8,good=[-1,4,4],bad=[-3,4,4];
  ok(cert(good,24,q,d)&&cert(bad,8,q,d),"individual FALSE certificates");
  ok(!Array.from({length:q},(_,t)=>t).some(t=>cert(good,t,q,d)&&cert(bad,t,q,d)),"no common certificate");
  let distributions=[],statistics=[];
  for(let mu=0;mu<=1;mu++){
    const counts=new Map(),set=new Set();
    for(let z=0;z<q;z++)for(let e1=-1;e1<=1;e1++)for(let e2=-1;e2<=1;e2++) {
      const a=source(good,z,[e1,0,0],mu,q,p,d),b=source(bad,z,[e2,0,0],mu,q,p,d);
      const k=JSON.stringify([a,b]);counts.set(k,(counts.get(k)||0)+1);
      set.add(mod(3*a[0]-b[0],p));
    }
    distributions.push(counts);statistics.push([...set].sort((a,b)=>a-b));
  }
  let tv=0;
  for(const k of new Set([...distributions[0].keys(),...distributions[1].keys()]))tv+=Math.abs((distributions[0].get(k)||0)-(distributions[1].get(k)||0));
  tv/=2*q*9;
  ok(tv===1,"unsafe reuse leaks perfectly despite individual false certificates");
  ok(statistics[0].every(v=>!statistics[1].includes(v)),"public statistic disjoint");
  const trueA=[-1,1,1,1],rs=[[1,1,0,0],[1,0,1,0],[1,0,0,1]];
  for(let mu=0;mu<4;mu++)for(let k=0;k<128;k++){
    const z=random()%Q,e=[signed(),signed(),signed(),signed()];
    const c=source(trueA,z,e,mu,Q,P,DELTA);
    for(const r of rs){
      ok(r.reduce((s,v,i)=>s+v*trueA[i],0)===0,"true witness kernel");
      const v=mod(r.reduce((s,x,i)=>s+x*c[i],0),P),target=64*mu;
      const dist=Math.min(mod(v-target,P),mod(target-v,P));
      ok(dist<=1,"every original witness opens same root word");
      trueOpenings++;
    }
  }
  return {run:"R78-COMMON-SHIFT-SOURCE-COIN-REUSE-20261104",status:"RESTRICTED_CERTIFIED_FALSE_JOINT_VIEW_ONLY",assertions,pointwise_couplings:pointwise,adaptive_full_public_couplings:adaptive,true_original_openings:trueOpenings,misaligned_shared_coin_total_variation:tv,distinguishing_statistic_support:statistics,limitations:"Toy exact algebra; no new hard-TRUE extractor, generic FALSE proof, 128-bit or QPT hardness demonstration"};
})(),null,2));
