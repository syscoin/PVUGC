// R62 connected-JavaScript finite algebra/transcript checker. NO QPT/security claim.
const Q=512,M=27,N=2,DELTA=128,ERR=1;let seed=6204,cnt=0;
function ck(a){if(!a)throw Error('assertion '+cnt);cnt++}
function rnd(){seed=(seed+0x6D2B79F5)>>>0;let x=seed;x=Math.imul(x^(x>>>15),x|1);x^=x+Math.imul(x^(x>>>7),x|61);return (x^(x>>>14))>>>0}
function mod(v){return ((v%Q)+Q)%Q}
function matrix(){return Array.from({length:M},()=>[rnd()%Q,rnd()%Q])}
function find2(A){const h=13,v=A.slice(1),d=new Map();for(let mask=0;mask<(1<<h);mask++){
 let a=0,b=0;for(let j=0;j<h;j++)if((mask>>j)&1){a+=v[j][0];b+=v[j][1]}const key=mod(a)+','+mod(b);if(!d.has(key))d.set(key,[]);d.get(key).push(mask)}
 const out=[];for(let mask=0;mask<(1<<(v.length-h));mask++){
 let a=A[0][0],b=A[0][1];for(let j=0;j<v.length-h;j++)if((mask>>j)&1){a+=v[h+j][0];b+=v[h+j][1]}
 const opts=d.get(mod(-a)+','+mod(-b))||[];for(let left of opts){const r=[1,...Array.from({length:h},(_,j)=>(left>>j)&1),...Array.from({length:v.length-h},(_,j)=>(mask>>j)&1)];ck(r.length===M&&[0,1].every(j=>mod(r.reduce((s,x,i)=>s+x*A[i][j],0))===0));out.push(r);if(out.length===2)return out}}
 return out}
function lwelike(A,bit){const s=[rnd()%Q,rnd()%Q],e=A.map(()=>rnd()%3-1),y=A.map((row,i)=>mod(row[0]*s[0]+row[1]*s[1]+e[i]));return {y,b:y.map((v,i)=>mod(v+(i===0?DELTA*bit:0)))} }
function open(w,b){const v=mod(b.reduce((s,x,i)=>s+x*w[i],0)),d0=Math.min(v,Q-v),t=mod(v-DELTA),d1=Math.min(t,Q-t);ck(Math.min(d0,d1)<=M*ERR&&d0!==d1);return +(d1<d0)}
function toyG(K,L){let x=(K^0x9e3779b9)>>>0;return Array.from({length:L},()=>{x=(Math.imul(x,1103515245)+12345)>>>0;return x&255})}
function digest(x){let h=2166136261;for(let c of String(x)){h=Math.imul((h^c.charCodeAt(0)),16777619)>>>0}return h.toString(16)}
function whole(ctx,A,C,D,kb,rel){const base=JSON.stringify([ctx,A,C,D,rel]);return [ctx,A,C,D,digest(kb+'CK'+base),digest(kb+'AUX'+base),rel]}
const A=matrix(),W=find2(A);ck(W.length===2&&W[0].some((a,i)=>a!==W[1][i]));
const Ar=matrix();Ar[0]=Ar[1].map(v=>mod(-v));const rw=[1,1,...Array(M-2).fill(0)];ck([0,1].every(j=>mod(Ar.reduce((s,row,i)=>s+row[j]*rw[i],0))===0));
let openings=0,relatedOpenings=0,joint=0,hybrids=0;
for(let t=0;t<64;t++){
 const K=rnd()%256,kb=rnd()%256,sig=Array.from({length:32},()=>rnd()%256),D=sig.map((v,i)=>v^toyG(K,32)[i]);
 const mu=[...Array.from({length:8},(_,i)=>(K>>(7-i))&1),...Array.from({length:8},(_,i)=>(kb>>(7-i))&1)];
 const data=mu.map(bit=>lwelike(A,bit)),C=data.map(x=>x.b);
 const Kr=rnd()%256,kbr=rnd()%256,rmu=[...Array.from({length:8},(_,i)=>(Kr>>(7-i))&1),...Array.from({length:8},(_,i)=>(kbr>>(7-i))&1)];
 const Cr=rmu.map(bit=>lwelike(Ar,bit).b),Drel=toyG(Kr,32);let rbits=Cr.map(b=>open(rw,b));ck(parseInt(rbits.slice(0,8).join(''),2)===Kr&&parseInt(rbits.slice(8).join(''),2)===kbr);relatedOpenings++;
 const rel=['related-open-true',whole(['related',t],Ar,Cr,Drel,kbr,null),rw,Kr,kbr];
 const v=whole(['target',t],A,C,D,kb,rel);
 for(let w of W){const bits=C.map(b=>open(w,b)),k=parseInt(bits.slice(0,8).join(''),2),kk=parseInt(bits.slice(8).join(''),2);ck(k===K&&kk===kb);ck(D.every((b,i)=>(b^toyG(k,32)[i])===sig[i]));ck(JSON.stringify(whole(['target',t],A,C,D,kk,rel))===JSON.stringify(v));openings++}
 const i=t%mu.length,challenge=data[i].y,sim=challenge.map((a,j)=>mod(a+(j===0?DELTA*mu[i]:0)));
 ck(sim.every((x,j)=>x===C[i][j]));const Cp=C.slice();Cp[i]=sim;ck(JSON.stringify(whole(['target',t],A,Cp,D,kb,rel))===JSON.stringify(v));joint++;
 const unif=Array.from({length:M},()=>rnd()%Q);Cp[i]=unif.map((x,j)=>mod(x+(j===0?DELTA*mu[i]:0)));const vU=whole(['target',t],A,Cp,D,kb,rel);
 ck(vU[2][i].every((x,j)=>x===Cp[i][j]));ck(vU[4]!==v[4]);ck(vU[6]===rel);hybrids++;
}
ck(DELTA>2*M*ERR&&Q>2*(DELTA+M*ERR));ck(Q**N/2**(M-1)===1/256);ck(2*(8+8)*M===864);
const result={run:'R62-DUAL-LWE-SIS-20261104',assertions:cnt,distinct_actual_original_SIS_witnesses:W.length,true_original_openings:openings,independent_related_true_openings:relatedOpenings,exact_joint_challenge_couplings:joint,uniform_challenge_public_recomputations:hybrids,toy_q:Q,toy_n:N,toy_m:M,theoretical_false_probability_upper:1/256,qpt_hardness:'NOT_TESTED',generic_original_compiler:'UNPROVED'};
console.log(JSON.stringify(result));
