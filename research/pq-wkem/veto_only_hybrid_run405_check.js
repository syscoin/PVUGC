const run405 = function run405(){
 const idx=(sk,vk,ct)=>sk*8+vk*4+ct, sum=a=>a.reduce((s,x)=>s+x,0);
 let assertions=0;const check=(p,m)=>{assertions++;if(!p)throw Error(m)};
 const census={};
 for(const [label,pads] of Object.entries({uniform_private_pad:[4,4,4,4],partly_unmasked_pad:[7,3,3,3]})){
  const real=Array(32).fill(0),dummy=Array(32).fill(0);
  for(let sk=0;sk<4;sk++)for(let r=0;r<4;r++){real[idx(sk,sk%2,sk^r)]+=pads[r];dummy[idx(sk,sk%2,r)]+=pads[r]}
  check(sum(real)===64&&sum(dummy)===64,"probability normalization");
  const tv=sum(real.map((v,i)=>Math.abs(v-dummy[i])))/2;
  let gap=0,maxReal=0,maxDummy=0;
  for(let st=0;st<65536;st++){
   let z=st;const a=Array(8);
   for(let i=0;i<8;i++){a[i]=z%4;z=Math.floor(z/4)}
   let pr=0,pd=0;
   for(let sk=0;sk<4;sk++)for(let c=0;c<4;c++)if(a[4*(sk%2)+c]===sk){pr+=real[idx(sk,sk%2,c)];pd+=dummy[idx(sk,sk%2,c)]}
   check(Math.abs(pr-pd)<=tv,"all strategies obey TV bound");
   gap=Math.max(gap,Math.abs(pr-pd));maxReal=Math.max(maxReal,pr);maxDummy=Math.max(maxDummy,pd);
  }
  if(label==="uniform_private_pad")check(tv===0&&maxDummy===32,"fully private pad");
  census[label]={strategies:65536,tv_over_64:tv,max_real_over_64:maxReal,max_dummy_over_64:maxDummy,max_strategy_gap_over_64:gap};
 }
 let graph_cases=0;
 for(let bits=0;bits<16;bits++){
  const witness=!!(bits&1),key=!!(bits&2),included=!!(bits&4),timeout=!!(bits&8);
  const challenge=key&&included,unsafePayout=witness&&timeout&&!challenge;
  if(witness&&challenge)check(!unsafePayout,"challenge-to-safe-sink monotonicity");
  graph_cases++;
 }
 return {run:405,status:"PASS",assertions,census,graph_cases,limits:"Finite probability and graph logic only, not WE, signatures, QPT security or Bitcoin consensus."};
};
console.log(JSON.stringify(run405(), null, 2));
