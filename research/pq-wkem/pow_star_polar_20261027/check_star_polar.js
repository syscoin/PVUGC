'use strict';
// Reproducible exact local star-signal, full-quotient and dyadic polar checks.
// No BTC PoW validation or QPT cryptographic hardness claim.
let checks=0;const ok=(x,m)=>{if(!x)throw Error(m);checks++};
const parity=x=>{let z=0;while(x){z^=1;x&=x-1}return z};
function masks(h){let out=[];for(let eta=0;eta<2;eta++)for(let lam=0;lam<(1<<h);lam++){
 if(eta===1&&lam===0)continue;for(let beta=0;beta<2;beta++){
 let E=0;for(let i=0;i<h;i++){let bit=(lam>>i)&1;
 let v=i===0?(beta?[eta,eta^bit,0,0]:[0,0,eta,eta^bit]):(beta?[0,bit,0,0]:[0,0,0,bit]);
 for(let j=0;j<4;j++)E|=v[j]<<(4*i+j);
 }out.push(E)
 }}return out}
function sourceV(h,a,bs,cs){let v=0;for(let i=0;i<h;i++){
 let b=(bs>>i)&1,c=(cs>>i)&1;
 let u=[1^a^b^c,b^c,a^c,c];for(let j=0;j<4;j++)v|=u[j]<<(4*i+j)
 }return v}
function checkLocal(){let rows=[];for(let h=1;h<=5;h++){
 let m=masks(h),num=1<<h,den=(1<<(h+1))-1;
 ok(m.length===2*den,'law support');
 for(let a=0;a<2;a++)for(let bs=0;bs<(1<<h);bs++)for(let cs=0;cs<(1<<h);cs++){
 let v=sourceV(h,a,bs,cs),sum=0;for(let E of m)sum+=parity(v&E)?-1:1;
 let accepted=true;for(let j=0;j<h;j++)if(((cs>>j)&1)!==(a&((bs>>j)&1)))accepted=false;
 ok(sum*den===(accepted?num*m.length:0),'exact group Fourier law');
 }rows.push({h,maskOutcomes:m.length,bias:num+'/'+den});
 }return rows}
function pivotKernel(rows,n){let a=rows.slice(),p=[],k=0;for(let c=0;c<n;c++){
 let j=a.findIndex((v,i)=>i>=k&&((v>>>c)&1));if(j<0)continue;
 [a[k],a[j]]=[a[j],a[k]];for(let t=0;t<a.length;t++)if(t!==k&&((a[t]>>>c)&1))a[t]^=a[k];
 p.push(c);k++}
 let R=[];for(let c=0;c<n;c++)if(!p.includes(c)){
 let v=1<<c;for(let j=0;j<p.length;j++)if(parity(a[j]&v))v^=1<<p[j];
 for(let row of rows)ok(!parity(v&row),'kernel');R.push(v)
 }return R}
function quotient(falseInstance){let vars=['a','b','c','z','y'],wi={};vars.forEach((v,i)=>wi[v]=[1+2*i,2+2*i]);
 let starts=[11,15],rows=[];for(let v of vars)rows.push(1^(1<<wi[v][0])^(1<<wi[v][1]));
 let gates=[['a','b','z',0],['a','c','y',1]];
 gates.forEach(([u,v,z,neg],j)=>{let st=starts[j],ass=[];
 for(let a=0;a<2;a++)for(let b=0;b<2;b++)ass.push([a,b,(a&b)^neg]);
 rows.push(1^ass.reduce((m,_,i)=>m^(1<<(st+i)),0));
 [u,v,z].forEach((name,pos)=>{for(let val=0;val<2;val++){
 let row=1<<wi[name][val];ass.forEach((x,i)=>{if(x[pos]===val)row^=1<<(st+i)});rows.push(row)}})
 });
 for(let [name,val] of [['z',1],['y',0],...(falseInstance?[['a',0]]:[])])rows.push((1<<wi[name][1])^val);
 let R=pivotKernel(rows,19);const proj=v=>R.reduce((o,r,i)=>o|(parity(r&v)<<i),0);
 let M=masks(2),H=[new Map(),new Map()];for(let z=0;z<2;z++)for(let E of M){
 let Q=proj((E&15)<<11 | ((E>>>4)&15)<<15 | z); H[z].set(Q,(H[z].get(Q)||0)+1)
 }
 let modes=0;for(let a=0;a<(1<<R.length);a++){
 let v=0;R.forEach((r,i)=>{if((a>>i)&1)v^=r});
 let valid=!!(v&1)&&starts.every(st=>parity((v>>st)&15)&&(((v>>st)&15).toString(2).replace(/0/g,'').length===1));
 if(valid)modes++;
 let expectation=z=>Array.from(H[z]).reduce((s,[y,n])=>s+(parity(a&y)?-n:n),0);
 ok((expectation(1)-expectation(0))*7===(valid?-8*M.length:0),'whole quotient law');
 }
 ok((modes===0)===falseInstance,'source support truth');
 const canonical=m=>JSON.stringify([...m].sort((a,b)=>a[0]-b[0]));
 const distributionEqual=canonical(H[0])===canonical(H[1]);
 ok(distributionEqual===falseInstance,'exact entire false/true quotient distribution');
 return {false:falseInstance,modes,dimension:R.length,distributionEqual}
}
function isqrt(n){if(n<2n)return n;let x=1n<<BigInt(Math.ceil(n.toString(2).length/2));for(;;){let y=(x+n/x)>>1n;if(y>=x)return x;x=y}}
function polar(k,t,lam,num,den,limit){let P=t+lam+128,D=1n<<BigInt(P),a=BigInt(num),b=BigInt(den);
 let z=isqrt(((b*b-a*a)*D*D)/(b*b))+1n;
 for(let N=1;N<=limit;N*=2){if(N<k)continue;let v=[z];for(let j=1;j<N;j*=2){let out=[];
 for(let x of v){out.push((2n*x-(x*x)/D)>D?D:2n*x-(x*x)/D);
 out.push((x*x+D-1n)/D>D?D:(x*x+D-1n)/D)}v=out}
 let sum=v.sort((x,y)=>x<y?-1:x>y?1:0).slice(0,k).reduce((x,y)=>x+y,0n);
 if((sum<<BigInt(t+lam))<=D)return N;
 }return null}
let local=checkLocal(), full=[quotient(false),quotient(true)];
let star=polar(128,64,64,16,31,1<<18),baseline=polar(128,64,64,16,81,1<<18);
ok(star===8192&&baseline===65536,'polar sizing');
let star2=polar(128,64,64,256,961,1<<18);ok(star2===32768,'two group sizing');
console.log(JSON.stringify({status:'PASS',checks,local,full,polar:{k:128,tEffective:64,lambda:64,oneFourGateStarN:star,oneFourIndependentN:baseline,twoFourGateStarN:star2},
 scope:'finite algebra and dyadic polar certificates only; NOT a Bitcoin POW or QPT hardness test'},null,2));
