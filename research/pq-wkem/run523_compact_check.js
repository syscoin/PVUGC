function verifyRun523(){
 function mul(a,b,n,p){let r=0,cap=(1<<n)-1;while(b){if(b&1)r^=a;b>>>=1;a<<=1;if(a&(1<<n))a^=p;}return r&cap;}
 function power(a,e,n,p){let r=1;while(e){if(e&1)r=mul(r,a,n,p);a=mul(a,a,n,p);e>>>=1;}return r;}
 function inv(a,n,p){return a?power(a,(1<<n)-2,n,p):0;}
 function mask(d,s,alpha,gamma,n,p){return mul(alpha,inv(d^s,n,p),n,p)^gamma^s;}
 function roots(beta,alpha,n,p){
   let rows=[];
   let cols=Array.from({length:n},(_,j)=>mul(1<<j,1<<j,n,p)^mul(beta,1<<j,n,p));
   for(let i=0;i<n;i++){let row=((alpha>>i)&1)<<n;for(let j=0;j<n;j++)if((cols[j]>>i)&1)row|=1<<j;rows.push(row);}
   let piv=[],rank=0;
   for(let j=0;j<n;j++){let index=-1;for(let i=rank;i<n;i++)if((rows[i]>>j)&1){index=i;break;}if(index<0)continue;
     [rows[rank],rows[index]]=[rows[index],rows[rank]];
     for(let i=0;i<n;i++)if(i!==rank&&((rows[i]>>j)&1))rows[i]^=rows[rank];
     piv.push(j);rank++;
   }
   let free=[];for(let j=0;j<n;j++)if(!piv.includes(j))free.push(j);
   if(free.length>1)throw Error("kernel dimension");
   for(let i=rank;i<n;i++)if((rows[i]>>n)&1)throw Error("inconsistent observed mask");
   let result=[];for(let m=0;m<(1<<free.length);m++){let u=0;
     for(let k=0;k<free.length;k++)if((m>>k)&1)u|=1<<free[k];
     for(let i=0;i<rank;i++){let j=piv[i],other=(rows[i]&((1<<n)-1))&~(1<<j);let parity=0;for(let k=0;k<n;k++)if((other>>k)&(u>>k)&1)parity^=1;if((((rows[i]>>n)&1)^parity))u|=1<<j;}
     if((mul(u,u,n,p)^mul(beta,u,n,p))!==alpha)throw Error("bad root");
     result.push(u);
   }
   return result;
 }
 let result=[];
 for(const [n,p,alpha,gamma,exhaustive] of [[4,0x13,9,6,true],[8,0x11b,0x57,0x63,true],[16,0x1100b,0x947,0x4ac1,false]]){
  let checks=0,betaZero=0,allTwo=0,keyLists=0;const N=1<<n;
  const rounds=exhaustive?N:256;
  for(let i=0;i<rounds;i++){let s=exhaustive?i:(i*4099+17)&(N-1), references=exhaustive?N:3;
   for(let j=0;j<references;j++){
     let r=exhaustive?j:(i*173+j*131+3)&(N-1),x=(i*7+j*13+3)&(N-1);if(x===r)x^=1;
     let k=(i*11+j*17+5)&(N-1),delta=mask(r,s,alpha,gamma,n,p),beta=delta^gamma^r;
     let us=roots(beta,alpha,n,p).filter(u=>u!==0);if(beta===0)us.push(0);
     let choices=[...new Set(us.map(u=>u^r).filter(t=>mask(r,t,alpha,gamma,n,p)===delta))].sort((a,b)=>a-b);
     if(choices.length!==2||!choices.includes(s))throw Error("one-reference theorem failed");
     let anchor=k^mask(x,s,alpha,gamma,n,p);
     let keyOptions=[...new Set(choices.map(t=>anchor^mask(x,t,alpha,gamma,n,p)))];
     if(!keyOptions.includes(k)||keyOptions.length>2)throw Error("target-key recovery failed");
     betaZero+=beta===0?1:0;allTwo++;keyLists+=keyOptions.length===2?1:0;checks++;
   }
  }
  result.push({n,modulus:"0x"+p.toString(16),alpha:"0x"+alpha.toString(16),checks,beta_zero:betaZero,exactly_two_masters:allTwo,two_target_key_candidates:keyLists});
 }
 return {run:523,claim:"one static reference yields at most two seeds, without Q2 oracle",pass:true,total:result.reduce((s,x)=>s+x.checks,0),results:result,scope:"finite algebraic fixtures; not real native signing"};
}
console.log(JSON.stringify(verifyRun523(),null,2));
