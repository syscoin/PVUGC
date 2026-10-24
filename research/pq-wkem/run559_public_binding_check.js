function check559(){
  let assertions=0,fixtures=0,positiveGap=0,witnessPairs=0;
  const ok=v=>{if(!v)throw Error("Run 559 checker assertion");assertions++;};
  for(let n=2;n<=8;n++){
    const N=2**n;
    for(const a of [1,3,5])for(const b of [0,1,N/2])for(let Y=0;Y<N;Y++){
      const P=(a*Y+b)%N;
      let matches=0;
      for(let z=0;z<N;z++)if((a*z+b)%N===P){matches++;ok(z===Y);}
      ok(matches===1);
      for(const w of [2*Y,2*Y+1]){ok((a*Math.floor(w/2)+b)%N===P);ok(Math.floor(w/2)===Y);}
      witnessPairs++;
    }
    for(let r=0;r<n;r++){
      const d=2**r;
      for(let P=0;P<2**(n-r);P++){
        const fiber=[],nonfiber=[];
        for(let y=0;y<N;y++)(Math.floor(y/d)===P?fiber:nonfiber).push(y);
        ok(fiber.length===d);
        for(let h=0;h<=n;h++){
          const q=2**h,take=Math.min(d,q);
          const support=fiber.slice(0,take).concat(nonfiber.slice(0,q-take));
          ok(support.length===q);
          ok(new Set(support).size===q);
          const accepts=support.filter(y=>Math.floor(y/d)===P).length;
          ok(accepts===take);
          ok(accepts/q===Math.min(1,d/q));
          fixtures++;
          if(q>d){positiveGap++;ok(1-accepts/q>0)}
        }
      }
    }
  }
  return {run:559,status:"PASS",assertions_passed:assertions,binding_support_fixtures:fixtures,positive_entropy_gap_fixtures:positiveGap,two_witness_true_instances:witnessPairs,binding_bound:"Pr[Q(Z,Y')=1] <= d*2^-h",full_QPT_WKEM_security:false,toy_one_wayness:false};
}
console.log(JSON.stringify(check559(), null, 2));
