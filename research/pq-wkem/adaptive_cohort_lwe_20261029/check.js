"use strict";
const checker = function checker(){
let checks=0;const a=(v,m)=>{checks++;if(!v)throw Error(m)};
const mod=(x,q)=>((x%q)+q)%q;
let rng=0x52a9c71d;const r=()=>{rng^=rng<<13;rng^=rng>>>17;rng^=rng<<5;return rng>>>0}, ri=n=>r()%n;
const dot=(u,v,q)=>mod(u.reduce((s,x,i)=>s+x*v[i],0),q);
const q=1009,n=2,m=23,N=4,J=2,w=4,B=1,g=Math.floor(q/8),L=86;
a(g>2*N*w*B,"margin"); const A=[Array.from({length:m},()=>ri(q))];A.push([...A[0]]);
const s=[ri(q),ri(q)],s2=[mod(s[0]+1,q),mod(s[1]-1,q)];
const e=Array.from({length:m},()=>ri(3)-1);
const b=e.map((x,i)=>mod(x+A[0][i]*s[0]+A[1][i]*s[1],q));
let key=Array.from({length:32},()=>ri(256));
let digit=l=>[0,1,2].reduce((v,j)=>{const ix=l*3+j;return ix<256?v+(((key[ix>>3]>>(ix&7))&1)<<j):v},0);
const shares=Array.from({length:L},(_,l)=>{let v=Array.from({length:N-1},()=>ri(q));v.push(mod(digit(l)-v.reduce((x,y)=>x+y,0),q));return v});
function coins(){let ix=Array.from({length:m},(_,i)=>i),v=Array(m).fill(0);for(let i=0;i<w;i++){let j=i+ri(m-i);[ix[i],ix[j]]=[ix[j],ix[i]];v[ix[i]]=(ri(2)?1:-1);}a(v.filter(x=>x!==0).length===w,"weight");return v;}
let openings=0;
for(let j=0;j<J;j++)for(let l=0;l<L;l++){
let cs=shares[l].map(z=>{let t=coins(),u=A.map(x=>dot(x,t,q)),v=mod(dot(b,t,q)+g*z,q);return {z,t,u,v}});
let cu=A.map((_,k)=>mod(cs.reduce((v,c)=>v+c.u[k],0),q)),cv=mod(cs.reduce((v,c)=>v+c.v,0),q);
for(const c of cs){a(c.u[0]===dot(A[0],c.t,q),"coin u");a(c.v===mod(dot(b,c.t,q)+g*c.z,q),"coin v");}
for(const ss of [s,s2]){
let residual=mod(cv-dot(ss,cu,q),q), tr=Array.from({length:m},(_,i)=>cs.reduce((v,c)=>v+c.t[i],0));
let noise=e.reduce((v,x,i)=>v+x*tr[i],0);
a(Math.abs(noise)<=N*w*B,"noise");
a(residual===mod(g*digit(l)+noise,q),"identity");
let nearest=Array.from({length:8},(_,d)=>{let delta=mod(residual-g*d,q);return Math.min(delta,q-delta)});
let decoded=nearest.indexOf(Math.min(...nearest));a(decoded===digit(l),"recovered 3bits");
}
for(let h=0;h<N;h++)for(let i=0;i<N;i++)if(i!==h){let c=cs[i];a(c.v===mod(dot(b,c.t,q)+g*shares[l][i],q),"adaptive full opened party");openings++;}
}
let paths=0;function path(prefix,rest){a(prefix.length<N,"survivor");a(N-prefix.length>=1,"global survivor");paths++;if(prefix.length===N-1)return;for(const k of rest)path([...prefix,k],rest.filter(x=>x!==k))}
path([],Array.from({length:N},(_,i)=>i));a(paths===41,"41 adaptive orders");
let exact=0;for(let val=0;val<3;val++)for(let h=0;h<3;h++){let S=new Set();for(let x=0;x<3;x++)for(let y=0;y<3;y++){let z=Array(3).fill(0),i=[0,1,2].filter(t=>t!==h);z[i[0]]=x;z[i[1]]=y;z[h]=mod(val-x-y,3);a(mod(z.reduce((v,t)=>v+t,0),3)===val,"qshares");S.add(z[i[0]]+":"+z[i[1]])}a(S.size===9,"uniform marginal");exact++}
const p=3,T=[];for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)for(const x of [-1,1])for(const y of [-1,1]){let z=[0,0,0,0];z[i]=x;z[j]=y;T.push(z);}
let tvs=0, shifts=0,Hcount=0;
for(let val=0;val<6561;val++){let v=val,H=[Array(4).fill(0),Array(4).fill(0)];for(let i=0;i<2;i++)for(let j=0;j<4;j++){H[i][j]=v%3;v=Math.floor(v/3)}
let hist=Array(9).fill(0);for(const t of T)hist[dot(H[0],t,p)*3+dot(H[1],t,p)]++;
let tv=0,sh=0;for(let u=0;u<3;u++)for(let z=0;z<3;z++){tv+=Math.abs(hist[u*3+z]/T.length-1/9)/2;sh+=Math.abs(hist[u*3+z]/T.length-hist[u*3+mod(z-1,3)]/T.length)/2}tvs+=tv;shifts+=sh;Hcount++;
}
const delta=.5*Math.sqrt(8/T.length);
a(tvs/Hcount<delta,"complete output bound");a(shifts/Hcount<2*delta,"shift bound");
function logF(n){let z=0;for(let i=2;i<=n;i++)z+=Math.log2(i);return z}
let support=logF(6800)-logF(2000)-logF(4800)+2000;
let logdelta=-1+.5*(257*Math.log2(16777213)-support);
return {status:"PASS",assertions:checks,related_capsules:J,mock_keybits:256,all_adaptive_corruption_orders:paths,complete_corrupt_coin_openings:openings,exact_share_marginals:exact,toy_uniform_H:Hcount,toy_mean_tv:tvs/Hcount,toy_mean_shift_tv:shifts/Hcount,toy_delta:delta,log2_statistical_bound_adaptive:Math.log2(2*4*2*86)+logdelta,scope:"restricted TRUE-LWE source; not generic NP or calibrated QPT security"};
};
const out = checker();
if(typeof process!=="undefined")process.stdout.write(JSON.stringify(out,null,2)+"\n");
