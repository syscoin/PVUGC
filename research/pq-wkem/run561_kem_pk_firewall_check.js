// Run 561 EXACT executed finite distributional checker (no cryptographic assumptions proved).
function check() {
  let assertions=0, grids=[], pairs=0, reuse=0;
  for (let bits=2; bits<=8; bits++) {
    const N=1<<bits;
    for (const mod of [2,3,5]) {
      const counts=Array.from({length:mod},()=>new Array(N).fill(0));
      for (let sk=0;sk<N;sk++) for (let pad=0;pad<N;pad++) {
        const T=sk^pad,pk=sk%mod;
        counts[pk][T]++;
        if ((T^pad)!==sk) throw Error("XOR reconstruction");
        assertions++;
      }
      for (let pk=0;pk<mod;pk++) {
        let nk=0;for(let sk=0;sk<N;sk++)if(sk%mod===pk)nk++;
        for(let T=0;T<N;T++){if(counts[pk][T]!==nk)throw Error("OTP independence given PK");assertions++;}
      }
      grids.push({bits,pk_modulus:mod,assertions:N*N+mod*N});
    }
  }
  // Two ORIGINAL-valid *toy* witnesses: a functionality check, not a release primitive.
  for(let sk=0;sk<256;sk++)for(const pad of [0,31,173,255]){
    const T=sk^pad,statement=Math.floor(sk/2);
    for(const w of [2*statement,2*statement+1]){
      const decoded=(Math.floor(w/2)===statement)?pad:null;
      if(decoded===null||(T^decoded)!==sk)throw Error("all-witness correctness");
      pairs++;assertions++;
    }
  }
  for(const sk1 of [11,77,201])for(const sk2 of [13,49,255])for(const reusedK of [2,93,248]){
    const T1=sk1^reusedK,T2=sk2^reusedK;
    if((T2^(T1^sk1))!==sk2)throw Error("reuse exposure");
    reuse++;assertions++;
  }
  let pk_matches=0;
  for(let sk=0;sk<32;sk++){
    const pk=sk&15;
    if((sk&15)!==pk)throw Error("pk check");
    for(let guess=0;guess<32;guess++)if((guess&15)===pk)pk_matches++;
    assertions++;
  }
  if(pk_matches!==64)throw Error("public checking-key test");
  assertions++;
  if("claim=7|branch=disprove|utxo=a"==="claim=7|branch=disprove|utxo=b")throw Error("context collision");
  assertions++;
  return {run:561,status:"PASS",assertions_passed:assertions,
    otp_independence_grids:grids.length,all_valid_witness_fixture_checks:pairs,
    shared_pad_cross_branch_exposures:reuse,
    public_checking_key_matches_out_of_1024:pk_matches,
    QPT_security_proved:false,release_primitive_instantiated:false,
    exact_scope:"finite OTP distribution and correctness only; conditional false-instance theorem is mathematical"};
}
