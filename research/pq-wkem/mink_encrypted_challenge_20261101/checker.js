function main(){
const Q=257,N=3,M=40,G=128;let seed=0x5a71e,checks=0;
function rand(k){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return (seed>>>0)%k}
function ok(x){checks++;if(!x)throw new Error("failed "+checks)}
function mod(x){return ((x%Q)+Q)%Q}
function keygen(){let A=Array.from({length:M},()=>Array.from({length:N},()=>rand(Q)));let s=Array.from({length:N},()=>rand(Q));let e=Array.from({length:M},()=>rand(3)-1);let b=A.map((a,i)=>mod(a.reduce((z,x,j)=>z+x*s[j],e[i])));return {A,b,s}}
function enc(k,b,r){r=r||Array.from({length:M},()=>rand(2));let u=Array.from({length:N},(_,j)=>mod(k.A.reduce((z,a,i)=>z+a[j]*r[i],0)));let v=mod(k.b.reduce((z,x,i)=>z+x*r[i],G*b));return {u,v,r}}
function dec(k,c){let x=mod(c.v-k.s.reduce((z,v,i)=>z+v*c.u[i],0));let dist=t=>Math.min(mod(x-t),mod(t-x));return +(dist(G)<dist(0))}
function same(a,b){return JSON.stringify(a)===JSON.stringify(b)}
function check(k,c,b,r){return r.length===M&&r.every(x=>x===0||x===1)&&same(enc(k,b,r),{u:c.u,v:c.v,r})}
function bits(v,n){return Array.from({length:n},(_,i)=>(v>>>i)&1)}
function encryptNum(k,v,n){return bits(v,n).map(b=>enc(k,b))}
function openNum(k,cs,v){return cs.every((c,i)=>check(k,c,bits(v,cs.length)[i],c.r))}
function decryptNum(k,cs){return cs.reduce((z,c,i)=>z+(dec(k,c)<<i),0)}
const col=keygen(),ch=keygen();ok(4*M<Q-1);
for(let a=0;a<64;a++)for(let bit=0;bit<2;bit++)for(let k of [col,ch]){let c=enc(k,bit);ok(dec(k,c)===bit);ok(check(k,c,bit,c.r));ok(!check(k,c,1-bit,c.r))}
let E=[[0,1],[1,2],[0,2],[2,3],[3,4],[4,5],[3,5]],colors=[0,1,2,0,1,2];
for(let r=0;r<96;r++){
let e=rand(E.length),C=encryptNum(ch,e,3),P=[0,1,2];
for(let j=2;j>0;j--){let i=rand(j+1);[P[i],P[j]]=[P[j],P[i]]}
let real=colors.map(x=>P[x]),comm=real.map(x=>encryptNum(col,x,2));let [a,b]=E[e];
ok(openNum(ch,C,e));ok(real[a]!==real[b]);ok(openNum(col,comm[a],real[a]));ok(openNum(col,comm[b],real[b]));
ok(decryptNum(ch,C)===e);
let fake=Array.from({length:6},()=>rand(3));fake[a]=rand(3);fake[b]=(fake[a]+1+rand(2))%3;
let sim=fake.map(x=>encryptNum(col,x,2));
ok(fake[a]!==fake[b]);ok(openNum(col,sim[a],fake[a]));ok(openNum(col,sim[b],fake[b]));
}
let E4=[[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]],max=0;
for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++){let z=[a,b,c,d],good=E4.filter(([i,j])=>z[i]!==z[j]).length;ok(good<=5);max=Math.max(max,good)}
ok(max===5);
return {run:"MINK-ECZK-2026-11-01-T18",checks,toy:{q:Q,n:N,m:M,eta:1},honest_rounds:96,simulated_rounds:96,false_K4_assignments:81,max_good_K4_edges:max,quantum_hardness_tested:false};
}
return JSON.stringify(main(),null,2)+"\n";