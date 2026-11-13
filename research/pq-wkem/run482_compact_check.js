const run482CompactCheck = function run482CompactCheck(){
  let assertions=0, falseDist=0, trueFixtures=0, falseFixtures=0, crossReplays=0, reusedFresh=0, independentReject=0;
  const ok=(v,msg)=>{if(!v)throw new Error(msg);assertions++};
  const power=(a,n,p)=>{let r=1;for(;n>0;n=Math.floor(n/2)){if(n%2)r=r*a%p;a=a*a%p}return r};
  const f=s=>(5*s+7)%256;
  const R=(mode,y,s,j)=>mode===1 && (j===0||j===1) && f(s)===y;
  const vk=sk=>power(3,sk,257);
  const tag=(ctx,mode,y)=>((ctx*11+y*7+mode*29)%256)|1;
  const sign=(sk,m)=>(sk*m)%256;
  const verify=(pk,m,sig)=>power(3,sig,257)===power(pk,m,257);
  const encrypt=(mode,key,coin)=>mode===1?key:coin;
  for(let publicKey=0;publicKey<16;publicKey++){
    for(let chosenKey=0;chosenKey<16;chosenKey++){
      for(let coin=0;coin<16;coin++){
        ok(encrypt(0,publicKey,coin)===encrypt(0,chosenKey,coin),"false IND distribution");
      }
      falseDist++;
    }
  }
  for(let s=1;s<=48;s++){
    const y=f(s),ctx=s*3,sk=2*s-1,skOther=2*s+1;
    ok(R(1,y,s,0)&&R(1,y,s,1),"two valid ORIGINAL witnesses");
    ok(!R(0,y,s,0),"false ORIGINAL instance");
    const cTrue=encrypt(1,sk,201),cFalse=encrypt(0,sk,201);
    ok(cTrue===sk,"true capsule publicly exposes secret");
    ok(cFalse===201,"false ciphertext independent of secret");
    ok(cTrue===encrypt(1,sk,37),"all witness same secret");
    const mTrue=tag(ctx,1,y),mFalse=tag(ctx,0,y),pk=vk(sk);
    ok(mTrue!==mFalse,"domain messages differ");
    const sigTrue=sign(sk,mTrue);
    ok(verify(pk,mTrue,sigTrue),"true authorization");
    ok(!verify(pk,mFalse,sigTrue),"replay blocked");crossReplays++;
    const sigFalse=sign(cTrue,mFalse);
    ok(verify(pk,mFalse,sigFalse),"fresh authorization from reused key");reusedFresh++;
    ok(!verify(vk(skOther),mFalse,sigFalse),"independent key prevents reuse");independentReject++;
    trueFixtures++;falseFixtures++;
  }
  return {run:482,status:"PASS",assertions,finite_false_distribution_pair_cases:falseDist,finite_false_distribution_individual_checks:4096,true_fixtures:trueFixtures,false_fixtures:falseFixtures,replayed_signature_rejections:crossReplays,fresh_false_branch_signatures_with_reused_key:reusedFresh,independent_key_rejections:independentReject,toy_native_signature_is_PQ:false,toy_permutation_is_one_way:false,scope:"finite diagnostic only; theorem uses distinct stated QPT assumptions"};
};
console.log(JSON.stringify(run482CompactCheck(),null,2));
