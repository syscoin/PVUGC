'use strict';
// Run 500 exact small-domain multiview same-key parity falsifier.
// GF(2) algebra only: NOT a native PQ signer, local mixer, or WKEM.
let checks=0;
const chk=(c,m)=>{checks++;if(!c)throw Error(m)};
const parity=x=>{let p=0;while(x){p^=x&1;x>>>=1}return p};
function rank(rows){
  let pivots={};
  for(let x of rows){while(x){const b=31-Math.clz32(x);if(pivots[b]===undefined){pivots[b]=x;break}x^=pivots[b]}}
  return Object.keys(pivots).length;
}
function solve(rows,rhs,width){
  const eq=rows.map((r,i)=>r|(rhs[i]<<width));let lead=0;
  for(let j=0;j<width;j++){
    let p=lead;while(p<eq.length&&!((eq[p]>>>j)&1))p++;
    if(p===eq.length)return null;
    [eq[p],eq[lead]]=[eq[lead],eq[p]];
    for(let i=0;i<eq.length;i++)if(i!==lead&&((eq[i]>>>j)&1))eq[i]^=eq[lead];
    lead++;
  }
  const z=eq.slice(0,width).reduce((sum,v,i)=>sum|(((v>>>width)&1)<<i),0);
  chk(rows.every((r,i)=>parity(r&z)===rhs[i]),'linear solve');return z;
}
const cases=[];
for(let h=1;h<=3;h++)for(let s=0;s<=1;s++){
  const m=h+1+s,total=2**(h*m);let full=0,bit=0;
  for(let seed=0;seed<total;seed++){
    const a=Array.from({length:m},(_,i)=>(seed>>>(h*i))&((1<<h)-1));
    const q=a.map(r=>r|(1<<h));
    const canRecoverBit=rank(q)>rank(a);
    if(canRecoverBit)bit++;
    if(rank(q)===h+1){
      full++;const secret=(seed*17+7)&((1<<h)-1),b=seed&1;
      const z=a.map(r=>parity(r&secret)^b);
      chk(solve(q,z,h+1)===(secret|(b<<h)),'same-key full recovery');
    }
  }
  let formula=1;for(let j=0;j<h;j++)formula*=1-2**(j-(m-1));
  chk(Math.abs(full/total-formula)<1e-12,'exact probability');
  chk(bit>=full,'bit recovery dominates complete recovery');
  cases.push({hidden_bits:h,views:m,surplus:s,matrices:total,full_rank:full,bit_decodable:bit,exact_probability:formula});
}
chk(cases.length===6,'case count');
console.log(JSON.stringify({run:500,checks,cases,
 conclusion:'Sharing one hidden secret and one masked bit across h+1+s independent public parity views permits full linear recovery with probability >1-2^-s',
 limitation:'Finite public GF2 attack; not an actual PQ local-mixing system or a break of independent-key single-bit Goldreich-Levin.'},null,2));
