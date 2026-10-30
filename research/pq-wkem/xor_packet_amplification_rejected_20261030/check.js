// Offline standalone Node checker for xor_packet_amplification_rejected_20261030.
// Tests finite algebra, not quantum computational security.
'use strict';
let checks=0;
const ok=(x,m)=>{checks++;if(!x)throw Error(m)};
function source(m,fixed){
  const rows=[],t=[];
  function add(a,v){const r=Array(m).fill(0);for(const [i,x] of Object.entries(a))r[+i]=x;rows.push(r);t.push(v)}
  add({0:1,2:-1,3:-1},0);add({1:1,2:-1,4:-1},0);
  add({0:1,1:1,2:-1,5:1},1);
  if(fixed){add({0:1},0);add({1:1},1);add({2:1},1)}
  for(let i=6;i<m;i++)add({[i]:1},0);
  return [rows,rows.map((r,i)=>2*t[i]-r.reduce((a,b)=>a+b,0))];
}
const mul=(A,z)=>A.map(row=>row.reduce((s,x,i)=>s+x*z[i],0));
function valid(m,a,b){const c=a*b;return [a,b,c,a-c,b-c,1-a-b+c,...Array(m-6).fill(0)].map(v=>2*v-1)}
function bad(m){return [-1,1,1,-3,-1,1,...Array(m-6).fill(-1)]}
function tail(m){let d=new Map([[0,1n]]);
  for(const v of [3,...Array(m).fill(1)]){
    const next=new Map();for(const [k,n] of d)for(const e of [-1,0,1])next.set(k+e*v,(next.get(k+e*v)||0n)+n);d=next;
  }
  const num=[...d].filter(([e])=>Math.abs(e)>=m+2).reduce((s,[,n])=>s+n,0n);
  const den=3n**BigInt(m+1);ok(num===2n*BigInt(m+1),'closed form tail');
  ok([...d.values()].reduce((a,b)=>a+b,0n)===den,'convolution total');return [num,den];
}
const rows=[];
for(const m of [6,12,20,32,64]){
  const [A,U]=source(m,false),[F,V]=source(m,true),z=bad(m);
  for(const a of [0,1])for(const b of [0,1]){
    ok(JSON.stringify(mul(A,valid(m,a,b)))===JSON.stringify(U),'true ORIGINAL lift');
  }
  ok(JSON.stringify(mul(F,z))===JSON.stringify(V),'false pseudo-opening solves linear SOURCE');
  ok(z.some(x=>Math.abs(x)>1),'false pseudo-opening not an ORIGINAL witness');
  ok(z[3]===-3,'forced gate slack');
  const [pnum,pden]=tail(m),p=Number(pnum)/Number(pden);
  const needed=Math.ceil(128*Math.log(2)/(256*(-Math.log1p(-p))));
  ok(needed>0,'necessary packet count');
  rows.push({m,bad_packet_failure_num:String(pnum),bad_packet_failure_den:String(pden),
             necessary_packets_per_bit_for_256bit_key_128bit_target:String(needed)});
}
// Exhaustively validate center decoding for both interior digits, 3^7 noise strings.
const m=6,z=bad(m),g=2*(m+1)+1,q=487;
for(const bit of [0,1]){
  let failures=0;
  for(let n=0;n<3**(m+1);n++){
    let k=n;const noise=[];for(let i=0;i<m+1;i++){noise.push(k%3-1);k=Math.floor(k/3)}
    const E=noise[m]-z.reduce((s,x,i)=>s+x*noise[i],0);
    const center=g*(3+bit)+E;
    let best=-1,distance=Infinity;
    for(let digit=0;digit<8;digit++){
      let v=((center-g*digit)%q+q)%q,vv=Math.min(v,q-v);
      if(vv<distance){distance=vv;best=digit}
    }
    if(best!==3+bit)failures++;
  }
  ok(failures===2*(m+1),'exhaustive interior center failure');
}
const result={status:'NO_POSITIVE_WKEM_ADVANCE',repair:'XOR shares across independent noisy packets',
  closed_form_bad_packet_failure:'2*(m+1)/3^(m+1)',
  classical_early_recovery_lower_bound:'(1-p)^(L*T)',rows,assertions:checks};
console.log(JSON.stringify(result,null,2));
