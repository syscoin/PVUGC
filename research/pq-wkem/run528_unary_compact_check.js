function check() {
  let fixed=0,tight=0,branch=0,inverse=0,guard=0,bypass=0;
  const assert=(x)=>{if(!x) throw Error("assertion failed")};
  for(let k=1;k<=8;k++){
    const n=2**k;
    for(let T=0;T<Math.min(2*n,35);T++){
      for(let m=1;m<=Math.min(n,5);m++){
        const seen=new Set();
        for(let j=0;j<m;j++){
          let z=j*(T+1)%n;
          for(let t=0;t<=T;t++){seen.add(z);z=(z+1)%n;}
        }
        assert(seen.size<=Math.min(n,m*(T+1)));fixed++;
        if(m*(T+1)<=n){assert(seen.size===m*(T+1));tight++;}
      }
    }
    const F=(b,z,t)=>[t<k ? z^(b<<t) : z,(t+1)%(k+1)];
    const I=(b,z,t)=>{const p=(t-1+k+1)%(k+1);return [p<k?z^(b<<p):z,p];};
    for(let b=0;b<2;b++)for(let t=0;t<=k;t++)for(let z=0;z<n;z++){
      const [zz,tt]=F(b,z,t),[backz,backt]=I(b,zz,tt);
      assert(z===backz && t===backt);inverse++;
    }
    for(let K=0;K<4;K++)for(let w=0;w<n;w++){
      let z=0,t=0;
      for(let j=0;j<k;j++){[z,t]=F((w>>j)&1,z,t);}
      assert(z===w && t===k);branch++;
    }
  }
  for(let k=1;k<=6;k++){
    for(let K=1;K<=15;K++)for(let w=0;w<2**k;w++){
      const valid=w&1;
      for(let b=0;b<2;b++){
        const combined=(K*b)^(K*(b^valid));
        assert(combined===(valid?K:0));guard++;
        if(valid===0&&b===1){assert(K*b===K);bypass++;}
      }
    }
  }
  assert(fixed===980 && tight===589 && branch===2040 &&
    inverse===8192 && guard===3780 && bypass===945);
  return {run:528,status:"PASS",fixed_unary_bound_cases:fixed,
    tight_cases:tight,reversible_inverse_cases:inverse,
    selectable_witness_cases:branch,guarded_identity_cases:guard,
    false_witness_admission_bypass_cases:bypass,
    scope:"finite semantic algebra only; no QPT security or implemented mixer"};
}

process.stdout.write(JSON.stringify(check(),null,2)+'\n');
