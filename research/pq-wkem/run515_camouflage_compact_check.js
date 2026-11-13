function perms(n){let a=Array.from({length:n},(_,i)=>i),out=[];function rec(k){if(k===n){out.push(a.slice());return;}for(let i=k;i<n;i++){[a[k],a[i]]=[a[i],a[k]];rec(k+1);[a[k],a[i]]=[a[i],a[k]];}}rec(0);return out;}
function compose(f,g){return g.map(v=>f[v]);}
function inv(p){let q=[];p.forEach((v,i)=>q[v]=i);return q;}
function eq(a,b){return a.length===b.length&&a.every((v,i)=>v===b[i]);}
function guard(n,pred,delta){let N=1<<(n+2);return Array.from({length:N},(_,s)=>{let z=(s>>1)&((1<<n)-1),u=s>>(n+1);return s^((((u^delta)&1)&pred[z]));});}
function conj(p,q){return compose(p,compose(q,inv(p)));}
function must(v,msg){if(!v)throw Error(msg);}
let p4=perms(4),p8=perms(8),b=guard(0,[1],0),cnt={quotient4:0,recovery4:0,marginalFrames4:0,independentViews4:0,independentHistogramEqual:0,n8Pads:0,n8Identities:0};
let common=[new Set(),new Set()],hist=[new Map(),new Map()];
for(let p of p4){let seenD=new Set(),seenE=new Set();
for(let C of p4){let D=conj(p,C),E=conj(p,compose(C,b));must(eq(compose(inv(D),E),conj(p,b)),"quotient");cnt.quotient4++;
seenD.add(D.join(","));seenE.add(E.join(","));
for(let K of [0,1]){let a=p[K*2];must(Number(D[a]!==E[a])===K,"recovery");common[K].add(JSON.stringify([a,D,E]));cnt.recovery4++;}}
must(seenD.size===24&&seenE.size===24,"marginal");cnt.marginalFrames4++;}
must([...common[0]].every(k=>!common[1].has(k)),"common supports");
for(let p of p4){for(let C0 of p4){let D=conj(p,C0);for(let C1 of p4){let E=conj(p,compose(C1,b));for(let K of [0,1]){let key=JSON.stringify([p[2*K],D,E]);hist[K].set(key,(hist[K].get(key)||0)+1);cnt.independentViews4++;}}}}
must(hist[0].size===2304&&hist[1].size===2304,"support");
for(let [key,v] of hist[0])must(v===6&&hist[1].get(key)===v,"hist equality");
cnt.independentHistogramEqual=1;
let ctrue=0,cnull=0;
for(let p of p4)for(let C of p4){let D=conj(p,C),E=conj(p,compose(C,b));ctrue+=Number(D[0]===E[0]);}
for(let D of p4)for(let E of p4)cnull+=Number(D[0]===E[0]);
must(ctrue===288&&cnull===144,"collision frequencies");
let I8=Array.from({length:8},(_,i)=>i);
for(let C of p8){let D=C;for(let pred of [[0,0],[1,0],[1,1]])for(let delta of [0,1]){let B=guard(1,pred,delta),E=compose(C,B);must(eq(compose(inv(D),E),B),"eight quotient");must(D.filter((v,y)=>v===E[y]).length===8-2*(pred[0]+pred[1]),"fixed points");cnt.n8Identities++;}cnt.n8Pads++;}
must(cnt.n8Pads===40320&&cnt.n8Identities===241920,"counts");
return JSON.stringify({run:515,status:"PASS",counts:cnt,commonTrueEqual:[ctrue,576],randomPairEqual:[cnull,576],scope:"finite permutation identities only; not a WE break or QPT security proof"})+String.fromCharCode(10);
