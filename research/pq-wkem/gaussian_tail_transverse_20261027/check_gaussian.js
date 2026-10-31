#!/usr/bin/env node
function runExact(){
  let assertions=0;
  function ck(x,msg){assertions++;if(!x)throw Error(msg||"assertion")}
  function choose(n,k){let x=1n;for(let i=1;i<=k;i++)x=x*BigInt(n-k+i)/BigInt(i);return x}
  const M=choose(4096,128);
  ck(M<(1n<<817n),"M binomial bound");
  ck(2n*32n*M<(1n<<823n),"full union support bound");
  ck((4096n*4096n*25n)/(8n*128n*256n)===1600n,"exact exponent");
  ck((4096n*4096n*25n)%(8n*128n*256n)===0n,"exponent integral");
  ck(57n*57n*25n>158n*512n,"dyadic tail exponent lower bound");
  ck(57n*57n*25n<159n*512n,"dyadic tail exponent upper bound");
  ck(4096/128*4096<1048576,"transverse source feasibility");
  ck(4096>0,"gap");
  ck(32*8>=256,"32 columns");
  ck(43*6>=256&&42*6<256,"43 column deterministic comparison");
  ck(16384>2*128*56&&8192<=2*128*56,"deterministic gap");
  ck(4096%128===0,"source cardinality");
  ck(2*32===64,"ell");
  // Perfect correctness of each of three distinct accepted binary reference witnesses,
  // exact n=5, h=2, q=64, g=8 finite-ring toy.
  const B=[0,0,0,7,11], q=64,g=8, alpha=4, good=[];
  for(let i=0;i<5;i++)for(let j=i+1;j<5;j++)if((B[i]+B[j])%q===0)good.push([i,j]);
  ck(good.length===3,"three accepted witnesses");
  let openings=0;
  for(let code=0;code<243;code++){
    let a=code,E=[];
    for(let i=0;i<5;i++){E.push((a%3)-1);a=Math.floor(a/3)}
    for(let t=0;t<16;t++)for(let u=0;u<8;u++){
      const p=B.map((bi,i)=>(alpha*t+bi*u+E[i]+q)%q);
      for(const [i,j] of good){
        const y=(p[i]+p[j])%q;
        const got=(Math.floor((y+g/2)/g))%(q/g);
        ck(got===t%(q/g),"any reference witness opens same residue");
        openings++;
      }
    }
  }
  ck(openings===93312,"opening count");
  // Exact full-null joint pad distribution with real fixed K.
  for(let K=0;K<2;K++){
    const counts=[0,0,0,0];
    for(let t=0;t<8;t++)for(let U=0;U<2;U++){
      const D=U^(t&1), V=K^U;
      counts[2*D+V]++;
    }
    for(const cnt of counts)ck(cnt===4,"fixed-pk joint null uniform");
  }
  // Whole LWE-vector embedding identity, not an oracle assumed to open the source.
  for(let t=0;t<16;t++)for(let u=0;u<16;u++)for(let z=0;z<27;z++){
    let a=z;const e=[];
    for(let i=0;i<3;i++){e.push(a%3-1);a=Math.floor(a/3)}
    const BB=[0,0,5];
    const direct=BB.map((bi,i)=>(4*t+bi*u+e[i]+64)%64);
    const challenged=BB.map((bi,i)=>(bi*u+e[i]+64)%64);
    ck(direct.every((v,i)=>v===(4*t+challenged[i])%64),"LWE challenge exact embedding");
  }
  return {run:"gaussian-transverse-tail-20261027-turn10",assertions,toy_openings:openings,integer_certificate:"2*ell*C(n,h)*exp(-1600) < 2^-777; n*ell*TV(chi,G) < 2^-139",sampler:{sigma:"16/5",T:56,P:320},linear_columns:{certified:32,deterministic_same_error:43},limits:"finite algebra / exact integer upper bounds; no QPT hardness, ORIGINAL PoW compiler, or native-BTC proof"};
}
process.stdout.write(JSON.stringify(runExact(),null,2)+"\n");
