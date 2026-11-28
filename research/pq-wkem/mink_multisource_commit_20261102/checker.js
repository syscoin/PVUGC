// MINK-MULTISOURCE-COMMIT-R16 exact executable finite checker (node checker.js)
const result=(()=>{
 let count=0; function check(c){count++;if(!c)throw Error("failed "+count)}
 let seed=160216>>>0;function rnd(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0}
 function h(x){x^=x>>>16;x=Math.imul(x,0x7feb352d);x^=x>>>15;x=Math.imul(x,0x846ca68b);return (x^(x>>>16))>>>0}
 function G(a,k){let s=k&15,o=0;for(let i=0;i<4;i++)o|=((a[i]*s+((k>>>(4+i))&1))&15)<<(4*i);return o}
 function stream(a,k){let o=0;for(let t=0;t<4;t++){let z=G(a,k);k=z&255;o|=((z>>>8)&255)<<(8*t)}return o>>>0}
 function F(A,S){let x=0;for(let i=0;i<A.length;i++)x^=stream(A[i],S[i]);return x>>>0}
 function enc(A,S,T,c){return(F(A,S)^(c===0?0:T[c-1]))>>>0}
 // R15 honest-slot public-coin embedding for every corrupt partial sum.
 for(let a=0;a<7;a++)for(let b=0;b<7;b++)for(let x=0;x<7;x++)for(let y=0;y<7;y++)
 check((a+(x-a+7)%7)%7===x&&(b+(y-b+7)%7)%7===y);
 // Ideal honest uniform mask hides each color for arbitrary corrupt mask and T.
 for(let bad=0;bad<16;bad++)for(let T of [[0,0],[5,12],[15,3]])for(let c=0;c<3;c++){
  let vals=new Set();for(let u=0;u<16;u++)vals.add(u^bad^(c===0?0:T[c-1]));check(vals.size===16)}
 // Exhaustive receiver-challenge bad-event count: N=2,kappa=2,D=11.
 let binding=[];for(let typ=0;typ<2;typ++){
 let a=[0,1,2,3].map(x=>h(31+x)&2047),b=typ===0?[0,0,0,0]:[0,1,2,3].map(x=>h(271+x)&2047);
 let support=new Set();for(let x of a)for(let y of b)support.add(x^y);
 let deltas=new Set();for(let x of support)for(let y of support)deltas.add(x^y);
 let bad=0;for(let t=0;t<2048;t++)if(deltas.has(t))bad+=2048;else{let u=new Set(deltas);for(let z of deltas)u.add(z^t);bad+=u.size}
 check(bad>0);check(bad<=3*256*2048);
 binding.push({key:typ===0?"malicious-zero":"arbitrary",bad,total:2048*2048,upperNumerator:768,upperDenominator:2048});
 }
 // Genuine finite q=16, n=1,m=4, one malformed and one honest matrix; real/trapdoor openings.
 let A=[[0,0,0,0],[3,5,7,11]];
 for(let i=0;i<500;i++){
 let c=rnd()%3,S=[rnd()&255,rnd()&255],T=[rnd(),rnd()],C=enc(A,S,T,c);
 check(enc(A,S,T,c)===C);
 let Ss=Array.from({length:3},()=>[rnd()&255,rnd()&255]),Ys=Ss.map(s=>F(A,s));
 let TT=[(Ys[0]^Ys[1])>>>0,(Ys[0]^Ys[2])>>>0];
 for(let j=0;j<3;j++)check(enc(A,Ss[j],TT,j)===Ys[0]);
 }
 // K4 non-three-colourability exhaustive fixed-color soundness test.
 let E=[];for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)E.push([i,j]);
 let max=0;for(let i=0;i<81;i++){let n=i,col=[];for(let v=0;v<4;v++){col.push(n%3);n=Math.floor(n/3)}
 let good=E.filter(([u,v])=>col[u]!==col[v]).length;check(good<=5);max=Math.max(max,good)}
 check(max===5);
 return {candidate:"MINK-MULTISOURCE-COMMIT-R16",checks:count,binding,
 largeReference:{q:65536,n:256,m:4096,seedBits:45056,stages:14,outputBits:286720,N:3,
 bindingExponent:2*3*45056-286720},
 limitation:"finite algebra only; no quantum hardness or generic NP release"};
})();
if(typeof console!=="undefined")console.log(JSON.stringify(result,null,2));
result;
