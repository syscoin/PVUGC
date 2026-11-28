'use strict';
// Exact finite sanity checks for a black-box theorem; NOT a secure release.
let assertions = 0;
function check(b,msg){assertions++;if(!b)throw new Error(msg);}
function parity(x){let p=0;while(x){p^=x&1;x>>=1;}return p;}
const rows=[];
for(const [n,t] of [[4,1],[4,3],[6,2],[6,4],[8,4],[8,8]]){
  const N=1<<n, M=(1<<t)-1;let kp=0,good=0, we=0;
  for(let k=0;k<N;k++){
    const z=k>>t,guess=z<<t;kp+=Number(guess===k);
    for(let r=0;r<N;r++){
      const actual=parity(k&r);
      const pred=(r&M)?0:parity(guess&r);
      good+=Number(pred===actual);
      for(const bit of [0,1]){
        const c=bit^actual;
        we+=Number((c^pred)===bit);
      }
    }
  }
  check(kp*(1<<t)===N,'key posterior');
  check(good*(1<<(t+1))===(N*N)*((1<<t)+1), 'hardcore posterior');
  check(we===2*good,'WE bit / hard-core correspondence');
  rows.push({n,unknown:t,key_success:"1/"+(1<<t),
             parity_success:((1<<t)+1)+"/"+(1<<(t+1))});
}
let twoViews=0;
for(let k=0;k<256;k++){
  const hi=k>>4,lo=k&15;
  check(((hi<<4)|lo)===k,'related view');twoViews++;
}
console.log(JSON.stringify({run:428,assertions,rows,related_view_joint_reconstructions:twoViews,
  exact_test:'uniform K, Z=known prefix, random GL parity and bit-mask',
  security_claim:'none; toy finite posterior only',complete_pq_wkem:false},null,2));
