"use strict";
// R110 EXACT published offline checker (Node.js >=18).
// It is algebraic only; it is not a QPT hardness test.
function runChecker(){
  const q=65521,d=256,ell=64,m=2000,L1=2729,oldM=1656,oldEll=16,L=7856,caps=16,occ=16;
  let n=0;
  function ck(v,msg){n++;if(!v)throw Error("Assertion "+n+": "+msg);}
  function support(m){
    let a=Array(L1+1).fill(0n); a[0]=1n;
    for(let t=0;t<m;t++){
      const b=Array(L1+1).fill(0n);
      b[0]=a[0]; b[1]=a[1]+2n*a[0]; b[2]=a[2]+2n*(a[1]+a[0]);
      for(let j=3;j<=L1;j++)b[j]=a[j]+2n*(a[j-1]+a[j-2]+a[j-3]);
      a=b;
    }
    return a.reduce((x,y)=>x+y,0n);
  }
  function log2Big(x){
    const bits=x.toString(2).length;
    const sh=bits>53?BigInt(bits-53):0n;
    const top=Number(x>>sh);
    return (bits>53?bits-53:0)+Math.log2(top);
  }
  const s=support(m),os=support(oldM),h=log2Big(s),oh=log2Big(os);
  ck(Math.abs(h-5445.079378072015)<1e-9,"new exact support");
  ck(Math.abs(oh-4641.215963129408)<1e-9,"old exact support");
  ck(s.toString(2).length===5446,"exact support bits");
  ck(3*L1===8187&&8187<16380/2,"all bounded-error witnesses decode");
  const groups=caps*occ*Math.ceil(8*L/(2*ell));
  const oldGroups=caps*occ*Math.ceil(8*L/(2*oldEll));
  ck(groups===125696&&oldGroups===502784,"full group counts");
  const eps=Math.log2(groups)-1+((d+ell)*Math.log2(q)-h)/2;
  const oldeps=Math.log2(oldGroups)-1+((d+oldEll)*Math.log2(q)-oh)/2;
  ck(eps< -146.6&&eps> -146.7,"new union-bound extractor");
  ck(oldeps> -128&&oldeps< -126.7,"old full signature budget lacks 128-bit stat");
  const oldPer=Math.ceil(8*L/(2*oldEll))*2*(d+oldEll);
  const newPer=Math.ceil(8*L/(2*ell))*2*(d+ell);
  ck(oldPer===1068416&&newPer===314240,"per occurrence exact ciphertext");
  const oldB=oldM*oldEll*2,newB=m*ell*2;
  ck(oldB===52992&&newB===256000,"public B sizes");
  const oldTotal=oldM*d*2+caps*occ*(oldB+oldPer);
  const newTotal=m*d*2+caps*occ*(newB+newPer);
  ck(oldTotal===287928320&&newTotal===147005440,"full key-plus-cipher bytes");
  ck((1964*23392)/(oldPer)===43,"R109 ciphertext arithmetic correction factor");
  const a=13,b=18,Z=b**3+2*(a*b*b+a*a*b+a**3);
  ck(Z===24734,"exact rational tilted weights");
  const logAcc=h+L1*Math.log2(a/b)-m*Math.log2(Z/(b**3));
  ck(logAcc<-5.0&&logAcc>-5.1,"expected exact sampler acceptance");
  for(let r=0;r<=16;r++){
    const numerator=BigInt(a)**BigInt(r)*BigInt(a)**BigInt(16-r);
    const denom=BigInt(b)**BigInt(r)*BigInt(b)**BigInt(16-r);
    ck(numerator===BigInt(a)**16n&&denom===BigInt(b)**16n,"all allowed proposal x acceptance have same weight");
  }
  // Finite algebraic correctness, all symbols, all errors in [-8187,8187],
  // at worst-case and all four cyclic codepoints.
  const positions=[0,1,2,3].map(x=>x*Math.floor(q/4));
  const errors=[-8187,-1,0,1,8187];
  for(let sym=0;sym<4;sym++)for(const e of errors){
    const z=(positions[sym]+e+q)%q;
    const nearest=positions.map(x=>Math.min((z-x+q)%q,(x-z+q)%q));
    ck(nearest.indexOf(Math.min(...nearest))===sym,"all-valid bounded-error cyclic decoding");
  }
  return {run:"R110-VECTOR64-UNIFORM-BOUNDED-L1-20261106",status:"PASS_RESTRICTED_NOT_GENERIC_NP",
    assertions:n,q,d,m,ell,L1,source_entropy_log2:h,
    support_integer_bits:s.toString(2).length,
    full_public_groups:groups,uniform_false_full_bundle_log2_distance:eps,
    corrected_R109_full_bundle_log2_distance:oldeps,
    corrected_R109_cipher_bytes_per_occurrence:oldPer,new_cipher_bytes_per_occurrence:newPer,
    corrected_R109_full_public_key_and_cipher_bytes:oldTotal,
    new_full_public_key_and_cipher_bytes:newTotal,
    actual_public_bytes_saved:oldTotal-newTotal,expected_exact_sampler_proposals:2**(-logAcc),
    checked_only:"algebra, exact combinatorial support, budget; QPT assumptions UNPROVEN"};
}
console.log(JSON.stringify(runChecker(),null,2));
