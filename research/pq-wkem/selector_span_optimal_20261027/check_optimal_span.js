'use strict';
// Exact r=2,h=3 optimal affine-selector Fourier law and SOURCE full-quotient check.
const F=[1,2,3],h=3,r=2,N=15;let tests=0;
function ok(x,msg){if(!x)throw Error(msg);tests++}
function p(x){let b=0;while(x){b^=x&1;x>>>=1}return b}
function sp(rows){let a=new Set([0]);for(const v of rows){for(const x of [...a])a.add(x^v)}return [...a].sort((a,b)=>a-b)}
const triples=[];let Z=0;
for(let S=0;S<8;S++){let V=sp(F.filter((_,i)=>S>>i&1));Z+=V.length;
 for(const u of V)for(let beta=0;beta<4;beta++)triples.push({S,u,beta})}
ok(Z===23&&triples.length===92,'weighted span sampler');
for(let z=0;z<4;z++)for(let b=0;b<8;b++)for(let c=0;c<8;c++){
 let total=0,valid=true;
 for(let i=0;i<h;i++)if(((c>>i)&1)!==(((b>>i)&1)&p(F[i]&z)))valid=false;
 for(const {S,u,beta} of triples){let phase=p(u&(z^beta));
  for(let i=0;i<h;i++)if(S>>i&1)phase^=((c>>i)&1)^(p(F[i]&beta)&((b>>i)&1));
  total+=phase?-1:1}
 ok(total===(valid?32:0),'all local characters')}
function rows(pin){let a=[];for(let i=0;i<3;i++){
 a.push((15<<(3+4*i))|1);let u=12<<(3+4*i);if(i!==1)u^=2;if(i!==0)u^=4;a.push(u)}
 if(pin!=='all')a.push(2,4);if(pin==='false')a.push((1<<6)|1);return a}
function ker(rr){let a=rr.slice(),pv=[],top=0;
 for(let i=0;i<N;i++){let j=a.findIndex((v,k)=>k>=top&&((v>>i)&1));if(j<0)continue;
 [a[top],a[j]]=[a[j],a[top]];for(let k=0;k<a.length;k++)if(k!==top&&((a[k]>>i)&1))a[k]^=a[top];
 pv.push(i);top++}let B=[];for(let f=0;f<N;f++)if(!pv.includes(f)){
 let v=1<<f;for(let i=0;i<top;i++)if((a[i]>>f)&1)v^=1<<pv[i];B.push(v)}return B}
function project(B,v){return B.reduce((x,b,i)=>x|(p(b&v)<<i),0)}
function physical({S,u,beta}){let m=p(u&beta);if(u&1)m^=2;if(u&2)m^=4;
 for(let i=0;i<h;i++)if(S>>i&1){let a=p(F[i]&beta);for(let j=0;j<4;j++){
 let left=j>>1,right=j&1;if((left&right)^(a&right))m^=1<<(3+4*i+j)}}return m}
const masks=triples.map(physical),snapshots=[];
for(const pin of ['all','true','false']){
 const rr=rows(pin),B=ker(rr);let yes=0,no=0;
 for(let v=0;v<(1<<N);v++){if(!(v&1)||rr.some(x=>p(x&v)))continue;
 const valid=[0,1,2].every(i=>{let x=(v>>(3+4*i))&15;return x&&!(x&(x-1))});
 const sig=masks.reduce((a,e)=>a+(p(e&v)?-1:1),0);ok(sig===(valid?32:0),'SOURCE characters');
 if(valid)yes++;else no++}
 let C=[new Map(),new Map()];for(const e of masks)for(let bit=0;bit<2;bit++){
 let x=project(B,e^bit),M=C[bit];M.set(x,(M.get(x)||0)+1)}
 let eq=C[0].size===C[1].size&&[...C[0]].every(([x,v])=>C[1].get(x)===v);
 ok(eq===(pin==='false'),'exact false full law');snapshots.push({pin,yes,no,eq})}
const result={status:'PASS',checks:tests,Z,signal:'8/23',previous:'8/29',snapshots,
 scope:'Exact finite algebra and full quotient laws only; no QPT/PoW test'};
console.log(JSON.stringify(result,null,2));
