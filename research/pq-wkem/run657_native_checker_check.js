const checkRun657 = function checkRun657(){
  let assertions=0,fixtures=0;
  function ok(b){if(!b)throw Error("run657 finite identity failed at assertion "+(assertions+1));assertions++;}
  for(let bits=2;bits<=12;bits++){
    const N=2**bits;
    for(let free=0;free<Math.min(bits,5);free++){
      const mask=(N-1)^((2**free)-1);
      for(const seed of [0,Math.floor(N/3),N-1]){
        const vk=seed&mask;
        const accepts=k=>(k&mask)===vk;
        let count=0;for(let k=0;k<N;k++)if(accepts(k))count++;
        ok(count===2**free);ok(accepts(seed));
        const delta=count/N;
        ok(Math.abs((1-delta)-(N-count)/N)<1e-12);
        if(delta<1){
          const theta=Math.asin(Math.sqrt(delta));
          const rotations=Math.max(0,Math.round(Math.PI/(4*theta)-0.5));
          const success=Math.sin((2*rotations+1)*theta)**2;
          ok(success>=0 && success<=1.000000000001);
          ok(rotations<=Math.ceil(Math.PI/(4*Math.sqrt(delta))));
        }
        fixtures++;
      }
    }
  }
  const examples=[
    [128,384,128,64],
    [256,384,128,128],
    [256,256,64,96],
    [384,512,128,192]
  ].map(([seed,frontier,logM,expected])=>{
    const nativeExponent=seed/2,frontierExponent=(frontier-logM)/2;
    ok(Math.min(nativeExponent,frontierExponent)===expected);
    return {seed_bits:seed,frontier_bits:frontier,log2_valid_states:logM,
      native_query_exponent:nativeExponent,frontier_query_exponent:frontierExponent,
      generic_min_query_exponent:expected};
  });
  return {run:657,checker:"native_public_checkability_js",result:"passed",assertions,fixtures,
    bits_tested:"2..12",examples,scope:"Finite accepted-seed densities and Grover amplitude trigonometry; not a cryptographic security proof"};
};
console.log(JSON.stringify(checkRun657(),null,2));
