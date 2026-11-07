(function main(){
"use strict";
let seed=392392392>>>0,nassert=0;
const rnd=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0};
const rr=n=>rnd()%n;
const ok=(v,m)=>{nassert++;if(!v)throw Error(m+" #"+nassert)};
const shuffle=a=>{for(let i=a.length-1;i>0;i--){let j=rr(i+1);[a[i],a[j]]=[a[j],a[i]];}return a;};
function layers(n,L){let out=[];for(let h=0;h<L;h++){let w=shuffle(Array.from({length:n},(_,i)=>i)),g=[];for(let i=0;i<n;i+=3){let c=w.slice(i,i+3);g.push([c,shuffle(Array.from({length:1<<c.length},(_,k)=>k))]);}out.push(g);}return out;}
function evalP(x,lay){let a=x.slice();for(const l of lay){let b=a.slice();for(const [w,t] of l){let v=0;for(let k=0;k<w.length;k++)v|=a[w[k]]<<k;let z=t[v];for(let k=0;k<w.length;k++)b[w[k]]=(z>>k)&1;}a=b;}return a;}
function cone(lay,j){let c=new Set([j]);for(let h=lay.length-1;h>=0;h--){let d=new Set();for(const [w] of lay[h])if(w.some(v=>c.has(v)))for(const v of w)d.add(v);c=d;}return c;}
let exhaustive=0;
for(const [n,L,rep] of [[9,1,2],[12,2,1]])for(let t=0;t<rep;t++){const l=layers(n,L);for(let j=0;j<4;j++){const c=cone(l,j);ok(c.size<=3**L,"cone");for(let i=0;i<n;i++)if(!c.has(i))for(let z=0;z<(1<<n);z++){const a=Array.from({length:n},(_,v)=>(z>>v)&1),b=a.slice();b[i]^=1;ok(evalP(a,l)[j]===evalP(b,l)[j],"outside");exhaustive++;}}}
let samples=[];
for(const [n,L] of [[27,2],[81,3],[243,4],[512,4],[512,5],[1024,5]]){let flips=0,outside=0,top=0;for(let t=0;t<3;t++){let l=layers(n,L);for(let z=0;z<60;z++){let i=rr(n),j=rr(n),x=Array.from({length:n},()=>rnd()&1),y=x.slice();y[i]^=1;let c=cone(l,j);ok(c.size<=3**L,"width");top=Math.max(top,c.size);let flip=evalP(x,l)[j]^evalP(y,l)[j];ok(!flip||c.has(i),"input influence");if(!c.has(i)){outside++;ok(!flip,"zero influence");}flips+=flip;}}const b=Math.max(0,.5-Math.min(n,3**L)/n);samples.push({n,L,pairs:180,flips,outside,max_cone:top,certified_advantage_lower_bound:b});}
let even=0,flips=0;
function perm(p,r){if(!r.length){let inv=0;for(let i=0;i<8;i++)for(let j=i+1;j<8;j++)inv+=(p[i]>p[j]);if(!(inv&1)){even++;flips+=(p[0]^p[1])&1;}return;}for(let k=0;k<r.length;k++)perm(p.concat(r[k]),r.slice(0,k).concat(r.slice(k+1)));}
perm([],Array.from({length:8},(_,i)=>i));
ok(even===20160,"A8 size");ok(flips===11520,"A8 pair marginal");
return JSON.stringify({run:392,status:"PASS",assertions:nassert,exhaustive_outside_cone_pairs:exhaustive,even_A8:even,even_flip_A8:flips,samples,scope:"isolated forward 3-local random reversible circuit; no WKEM/RIO/security result"},null,2)+"\n";
})()
