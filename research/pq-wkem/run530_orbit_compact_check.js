// Run 530 compact honest-path orbit rank check; deterministic JavaScript.
"use strict";
let state=5302026>>>0;
function rnd(){state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;}
function gate(x,g){let [t,a,b,c]=g;if(t==="N")return x^(1<<a);
if(t==="C")return x^(((x>>>a)&1)<<b);
if(t==="S")return (((x>>>a)^(x>>>b))&1)?x^(1<<a)^(1<<b):x;
return x^(((x>>>a)&(x>>>b)&1)<<c);}
function frame(n,r){let G=[];function aff(){for(let j=0;j<n+2;j++){
let z=rnd()%3,a=rnd()%n,b=(a+1+rnd()%(n-1))%n;
G.push(z===0?["N",a,0,0]:(z===1?["C",a,b,0]:["S",a,b,0]));}}
aff();for(let i=0;i<r;i++){let a=rnd()%n,b=(a+1+rnd()%(n-1))%n;
let c=rnd()%n;while(c===a||c===b)c=(c+1)%n;
G.push(["T",a,b,c]);aff();}return G;}
function rank(V){let p={};let out=0;for(let x of V){while(x){let j=31-Math.clz32(x);if(p[j]!==undefined)x^=p[j];else{p[j]=x;out++;break;}}}return out;}
function test(k,h,r,ideal){let cw=Math.ceil(Math.log2(k+1)),n=k+cw+h,N=1<<n,q=k+r+2;
if(q>Math.min(1<<k,n+1))throw Error("bad q");
let F=Array.from({length:N},(_,i)=>i);
if(ideal){for(let i=N-1;i>0;i--){let j=rnd()%(i+1);[F[i],F[j]]=[F[j],F[i]];}}
else{let G=frame(n,r);F=F.map(s=>{for(let g of G)s=gate(s,g);return s;});}
if(new Set(F).size!==N)throw Error("non-permutation");
let I=new Int32Array(N);for(let s=0;s<N;s++)I[F[s]]=s;
let K=rnd()%(1<<h),anchor=F[K<<(k+cw)],outs=[];
function update(y,b){let s=I[y],z=s&((1<<k)-1),t=(s>>>k)&((1<<cw)-1),H=s>>>(k+cw);
if(t<=k){if(t<k && b)z^=1<<t;t=(t+1)%(k+1);}return F[(H<<(k+cw))|(t<<k)|z];}
for(let w=0;w<q;w++){let y=anchor;for(let j=0;j<k;j++)y=update(y,(w>>>j)&1);
if(I[y]!==((K<<(k+cw))|(k<<k)|w))throw Error("incorrect honest writer");
outs.push(y);}
if(new Set(outs).size!==q)throw Error("duplicate encoded states");
let v=outs.slice(1).map(y=>y^outs[0]),d=rank(v);
if(!ideal && d>k+r)throw Error("sparse rank violated");
return d===q-1;}
let sparse=0, ideal=0, details=[];
for(let [k,h,r] of [[3,5,0],[3,5,1],[4,5,2],[5,5,3],[5,6,5],[6,5,3]]){
let a=0,b=0;for(let i=0;i<24;i++){a+=test(k,h,r,false)?1:0;b+=test(k,h,r,true)?1:0;}
sparse+=a;ideal+=b;details.push({k,h,r,trials:24,sparse_full_rank:a,ideal_full_rank:b});}
if(sparse!==0 || ideal<80)throw Error("unexpected finite control");
return {run:530,status:"PASS",seed:5302026,sparse_trials:144,sparse_full_rank:sparse,ideal_trials:144,ideal_full_rank:ideal,details,
scope:"legitimate k-step public writer outputs; affine-span distinguisher only, not key recovery or a QPT security proof"};
