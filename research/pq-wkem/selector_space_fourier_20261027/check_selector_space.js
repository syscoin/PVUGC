'use strict';
const N=15,S=3,F=[1,2,3],ct={};
function check(x,k){if(!x)throw Error('FAIL '+k);ct[k]=(ct[k]||0)+1}
function bit(x,i){return (x>>>i)&1}
function parity(x){let p=0;while(x){p^=x&1;x>>>=1}return p}
function pc(x){let c=0;while(x){c+=x&1;x>>>=1}return c}
function rows(pin){let a=[];for(let i=0;i<3;i++){
a.push((15<<(S+4*i))|1);
let u=12<<(S+4*i);if(i!==1)u^=2;if(i!==0)u^=4;a.push(u)}
if(pin!=='all')a.push(2,4);
if(pin==='false')a.push((1<<(S+3))|1);
return a}
function kernel(rr){let a=rr.slice(),piv=[],top=0;
for(let c=0;c<N;c++){let j=-1;for(let t=top;t<a.length;t++)if(bit(a[t],c)){j=t;break}
if(j<0)continue;[a[top],a[j]]=[a[j],a[top]];
for(let k=0;k<a.length;k++)if(k!==top&&bit(a[k],c))a[k]^=a[top];
piv.push(c);top++;if(top===a.length)break}
let B=[];for(let f=0;f<N;f++){if(piv.includes(f))continue;let v=1<<f;
for(let k=0;k<top;k++)if(bit(a[k],f))v^=1<<piv[k];
B.push(v);check(rr.every(r=>parity(r&v)===0),'kernel')}return B}
let masks=[];for(let eta=0;eta<4;eta++)for(let lam=0;lam<8;lam++)for(let beta=0;beta<4;beta++){
if(lam===0&&eta!==0)continue;let m=parity(eta&beta);
if(eta&1)m^=2;if(eta&2)m^=4;
for(let i=0;i<3;i++){if(!bit(lam,i))continue;let z=parity(beta&F[i]);
for(let j=0;j<4;j++){let u=j>>1,v=j&1;if((u&v)^(z&v))m^=1<<(S+4*i+j)}}masks.push(m)}
check(masks.length===116,'mask_count');
function accept(v){return bit(v,0)&&[0,1,2].every(i=>pc((v>>>(S+4*i))&15)===1)}
function proj(B,e){let x=0;for(let i=0;i<B.length;i++)x|=parity(B[i]&e)<<i;return x}
function eq(A,B){return A.size===B.size&&[...A].every(([x,y])=>B.get(x)===y)}
function fixture(pin){let B=kernel(rows(pin)),states=[];
for(let i=0;i<(1<<B.length);i++){let v=0;for(let j=0;j<B.length;j++)if(bit(i,j))v^=B[j];states.push(v)}
let yes=0,no=0;for(let v of states){if(!bit(v,0))continue;
let signal=masks.reduce((a,e)=>a+(parity(e&v)?-1:1),0);
if(accept(v)){yes++;check(signal===32,'valid_filter')}
else{no++;check(signal===0,'invalid_filter')}}
let P=new Map(),Q=new Map(),shift=proj(B,1);
for(let e of masks){let x=proj(B,e),y=x^shift;P.set(x,(P.get(x)||0)+1);Q.set(y,(Q.get(y)||0)+1)}
let equal=eq(P,Q);if(pin==='false')check(yes===0&&equal,'false_full_view');
else check(yes>0&&!equal,'true_full_view');
return {pin,quotient_bits:B.length,valid_modes:yes,invalid_modes:no,entire_laws_equal:equal}}
for(let a=0;a<2;a++)for(let y=0;y<2;y++)for(let nu=0;nu<2;nu++){
let u=a^y,c=(u&y)^nu,ell=(u&y)^(a&y);
check(ell===y&&((c^nu^ell)===(a&y)),'affine_normalization')}
let planes=[];for(let i=0;i<12;i++){let l=F[Math.floor(i/4)],t=1<<(i+2);planes.push(new Set([l,t,l^t]))}
check([...planes[0]].filter(x=>planes.every(p=>p.has(x))).length===0,'no_global_factor');
let newer=4096/16381,older=4096/29791;
check(newer>older&&older>Math.pow(2/3,12),'improved_rate');
check(8/29<Math.pow(2/3,3),'merge_requires_gain');
function cap(r){let p=(1-r)/2;return 1+p*Math.log2(p)+(1-p)*Math.log2(1-p)}
let cases=['all','true','false'].map(fixture);
return {status:'PASS',assertions:Object.values(ct).reduce((a,b)=>a+b,0),
groups:Object.fromEntries(Object.entries(ct).sort((a,b)=>a[0].localeCompare(b[0]))),
fixtures:cases,signal:{old:'4096/29791',new:'4096/16381',bias_gain:newer/older,capacity_gain:cap(newer)/cap(older)},scope:'Exact finite distribution identities; no QPT hardness or Bitcoin benchmark'};
