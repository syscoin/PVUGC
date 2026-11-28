const checker=function checker(){
 let checks=0;function ok(x,m){checks++;if(!x)throw Error(m)}
 const q=16777213n,n=256n,m=4469n,w=2004,L=52,B=128,g=524287;
 function comb(a,b){let s=1n;for(let i=1n;i<=BigInt(b);i++)s=s*(BigInt(a)-i+1n)/i;return s}
 const J=BigInt(400*3*2*L),lhs=J*J*(q**n-1n)*(1n<<256n),T=(1n<<BigInt(w))*comb(m,w);
 ok(lhs<=4n*T,"exact 400-scope statistical bound");
 ok(lhs>4n*(1n<<2003n)*comb(m,2003),"w=2003 fails");
 ok(g>2*B*(w+1)&&Number(q)-31*g>2*B*(w+1),"both decoding gaps");
 const old=n*m*3n+400n*(n*BigInt(L)+3n*(m+BigInt(L)))*3n;
 const now=n*m*3n+400n*(3n*n*BigInt(L)+3n*(m+BigInt(L)))*3n;
 ok(old===35682192n&&now===67630992n&&now-old===31948800n,"storage");
 function mul(a,b){let v=0;for(let i=0;i<8;i++){if(b&1)v^=a;const h=a&128;a=(a<<1)&255;if(h)a^=27;b>>=1;}return v}
 function inv(a){for(let j=1;j<256;j++)if(mul(a,j)===1)return j;throw Error("bad GF inverse")}
 let pairCount=0;
 for(let k=0;k<256;k++)for(let v=0;v<256;v++){
  const s=[1,2,3].map(a=>k^mul(a,v));
  for(const [i,j] of [[0,1],[0,2],[1,2]]){
   const r=mul(s[i]^s[j],inv((i+1)^(j+1)));
   ok((s[i]^mul(i+1,r))===k,"same master from every share pair");pairCount++;
  }
 }
 for(const a of [1,2,3])for(const share of [0,47,255])for(let k=0;k<256;k++){
  ok((k^mul(a,mul(share^k,inv(a))))===share,"one share permits all masters");
 }
 let tvNumer=0;
 for(let a=0;a<5;a++)for(let b=0;b<5;b++)for(let c=0;c<5;c++){
  const hist=[0,0,0,0,0];
  for(const x of [a,b,c]){hist[x]++;hist[(5-x)%5]++}
  ok(hist.reduce((x,y)=>x+y,0)===6,"tiny T mass");
  tvNumer+=hist.reduce((s,x)=>s+Math.abs(5*x-6),0);
 }
 ok(tvNumer===2496,"tiny average TV=208/625");
 let seed=20261030;function rnd(s){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return (seed>>>0)%s}
 function dist(x,y){const z=(x-y+257)%257;return Math.min(z,257-z)}
 let releases=0;
 for(let trial=0;trial<32;trial++){
  const A=[11,41,97,173],K=rnd(256),V=rnd(256);
  const S=[1,2,3].map(a=>K^mul(a,V)),D=[];
  for(let i=0;i<3;i++){
   const r=rnd(257),ec=A.map(()=>rnd(3)-1);
   const c=A.map((a,j)=>(a*r+ec[j]+257)%257);let val=0;
   for(let bit=0;bit<8;bit++){
    const d=(A[i]*r+rnd(3)-1+64*((S[i]>>bit)&1)+257)%257;
    const t=(d-c[i]+257)%257;const b=+(dist(t,64)<dist(t,0));
    ok(b===((S[i]>>bit)&1),"packet-specific legal opening");val|=b<<bit;
   }
   ok(val===S[i],"full share");D.push(val);
   for(let j=0;j<3;j++)if(j!==i)ok(A[j]!==A[i],"opening for i invalid for j");
  }
  for(const [i,j] of [[0,1],[0,2],[1,2]]){
   const v=mul(D[i]^D[j],inv((i+1)^(j+1)));
   ok((D[i]^mul(i+1,v))===K,"two distinct packet targets reconstruct same key");releases++;
  }
 }
 return {checks,pair_GF256_reconstructions:pairCount,toy_packet_pairs:releases,
 exact_toy_leftover_TV:"208/625",weight_2003_fails:true,weight_2004_passes:true,
 normal_decode_margin:g-2*B*(w+1),wrap_decode_margin:Number(q)-31*g-2*B*(w+1),
 prior_public_bytes:String(old),new_public_bytes:String(now),extra_public_bytes:String(now-old),
 ORIGINAL_Lift:"UNSOLVED",QPT_hardness:"NOT TESTED",native_signatures:"NOT TESTED"};
};
console.log(JSON.stringify(checker(),null,2));
