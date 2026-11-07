(()=>{
 const N=(cb,n)=>1<<(cb+n+2);
 const enc=(u,c,z,t,cb,n)=>((((u<<cb)|c)<<n|z)<<1)|t;
 const dec=(s,cb,n)=>[s>>(cb+n+1),(s>>(n+1))&((1<<cb)-1),(s>>1)&((1<<n)-1),s&1];
 const map=(cb,n,fn)=>Array.from({length:N(cb,n)},(_,s)=>enc(...fn(...dec(s,cb,n)),cb,n));
 const eq=(a,b)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
 const conj=(P,B)=>{let A=Array(P.length);for(let i=0;i<P.length;i++)A[P[i]]=P[B[i]];return A;};
 const must=(b,t)=>{if(!b)throw Error(t);};
 const perms=n=>{let a=Array.from({length:n},(_,i)=>i),o=[];function rec(i){if(i===n){o.push(a.slice());return;}for(let j=i;j<n;j++){[a[i],a[j]]=[a[j],a[i]];rec(i+1);[a[i],a[j]]=[a[j],a[i]];}}rec(0);return o;};
 const T=(cb,n)=>map(cb,n,(u,c,z,t)=>[c===0?u^1:u,c,z,t]);
 const G=(cb,n,c,pred,tagged=true)=>map(cb,n,(u,d,z,t)=>[u,d,z,t^((tagged?Number(d===c):1)&u&pred(z))]);
 const L=(cb,n)=>map(cb,n,(u,c,z,t)=>[u,c,z^1,t]);
 const S=(cb,n,r)=>map(cb,n,(u,c,z,t)=>[u,c===0?r:c===r?0:c,z,t]);
 function trial(P,cb,n,refs){let P2=T(cb,n).map(t=>P[t]),Bs=refs.map(([c,p])=>G(cb,n,c,p));if(n)Bs.push(L(cb,n));for(let B of Bs)must(eq(conj(P,B),conj(P2,B)),"joint action table coupling");for(let k of [0,1]){must(P[enc(k,0,0,0,cb,n)]===P2[enc(k^1,0,0,0,cb,n)],"target anchor coupling");for(let [c] of refs)must(P[enc(k,c,0,0,cb,n)]===P2[enc(k,c,0,0,cb,n)],"ref anchor coupling");for(let z=0;z<(1<<n);z++)for(let B of Bs.slice(0,refs.length)){let x=P[enc(k,0,z,0,cb,n)];must(conj(P,B)[x]===x,"target orbit protected");}}
 let [r,p]=refs[0], V=conj(P,S(cb,n,r)),A=conj(P,Bs[0]), W=n?conj(P,L(cb,n)):null;must(p((1<<n)-1),"valid reference");for(let k of [0,1]){let x=P[enc(k,0,0,0,cb,n)],y=V[x];if(W)y=W[y];must(Number(A[y]!==y)===k,"sector switch key extraction");}return true;}
 const counts={exhaustiveS8:0,S8Recovered:0,witnessS16:0,S16Recovered:0,untaggedRecovered:0,twoRefS16:0,twoRefRecovered:0};
 for(let P of perms(8)){trial(P,1,0,[[1,_=>1]]);counts.exhaustiveS8++;counts.S8Recovered+=2;}
 let seed=516;const rand=()=>{seed^=(seed<<13);seed^=(seed>>>17);seed^=(seed<<5);return seed>>>0;};
 function sample(n){let P=Array.from({length:n},(_,i)=>i);for(let j=n-1;j>0;j--){let k=rand()%(j+1);[P[j],P[k]]=[P[k],P[j]];}return P;}
 for(let j=0;j<384;j++){let P=sample(16);trial(P,1,1,[[1,z=>Number(z===1)]]);counts.witnessS16++;counts.S16Recovered+=2;let U=conj(P,G(1,1,1,z=>Number(z===1),false)),W=conj(P,L(1,1));for(let k of [0,1]){let x=P[enc(k,0,0,0,1,1)],y=W[x];must(Number(U[y]!==y)===k,"untagged recovery");counts.untaggedRecovered++;}}
 for(let j=0;j<256;j++){trial(sample(16),2,0,[[1,_=>1],[2,_=>1]]);counts.twoRefS16++;counts.twoRefRecovered+=2;}
 must(counts.exhaustiveS8===40320&&counts.S8Recovered===80640&&counts.witnessS16===384&&counts.S16Recovered===768&&counts.untaggedRecovered===768&&counts.twoRefS16===256&&counts.twoRefRecovered===512,"counts");
 return JSON.stringify({run:516,status:"PASS",counts,scope:"ideal claim-sector action coupling; public cross-sector switching falsifier, not practical cryptography"},null,2)+"\n";
})()
