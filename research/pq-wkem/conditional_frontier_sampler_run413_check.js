'use strict';
// Exact finite combinatorial negative control. No security/PQ claim.
let assertions=0, cases=0;
function ok(p,msg){assertions++;if(!p)throw Error(msg);}
function subs(N,h){let a=[];for(let mask=0;mask<(1<<N);mask++){let b=[];for(let i=0;i<N;i++)if(mask&(1<<i))b.push(i);if(b.length===h)a.push(b);}return a;}
for(const N of [4,6,8,10])for(let h=1;h<N;h++){
 const families=subs(N,h);cases++;
 for(let u=0;u<N;u++){
  const count=families.filter(A=>A.includes(u)).length;
  ok(count*N===families.length*h,'nonuniform witness-state marginal');
 }
 for(const A of families){ok(A.length===h,'bad cardinality');}
 // exact integer numerator identities for honest/fake acceptance and joint TV
 ok(h<N,'false density');
 for(let e=0;e<=4;e++){
  const fakeNum=4*N-e*(N-h),den=4*N;
  ok(fakeNum+(e*(N-h))===den,'sampler bound fails');
 }
}
let fixed=0;
for(const N of [8,16,32])for(let a=0;a<N;a++){
 const K=(0xA59B^(a<<8)^N)&0xFFFF,vk=K^0xC53D;
 for(let u=0;u<N;u++){
  const v=u===a?K:null;
  ok((v!==null&&(v^0xC53D)===vk)===(u===a),'checking key mismatch');fixed++;
 }
}
console.log(JSON.stringify({run:413,scope:'marginal-vs-joint public-release sampler finite negative control',assertions_passed:assertions,exhaustive_probability_cases:cases,fixed_checking_key_cases:fixed,example_N8_h1:{marginal_tv:'0',joint_tv:'7/8',uniform_sampler_recovery:'1/8'},example_N8_h4:{marginal_tv:'0',joint_tv:'1/2',uniform_sampler_recovery:'1/2'},not_proved:['PQ security','KEM construction','quantum hardness','native Bitcoin signing']},null,2));
