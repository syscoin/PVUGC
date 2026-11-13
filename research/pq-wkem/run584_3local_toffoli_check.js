'use strict';
let checks=0;
function ok(x){checks++;if(!x)throw Error('assertion '+checks);}
function gates(n){let g=[[0,1,2]];for(let j=3;j<n-1;j++)g.push([j-1,j+1,j]);return g;}
function step(x,g){return ((x>>g[0])&1)&&((x>>g[1])&1)?x^(1<<g[2]):x;}
function U(x,g){for(const t of g)x=step(x,t);return x;}
function parity(a){let seen=new Set(),cycles=0;for(let i=0;i<a.length;i++){if(seen.has(i))continue;cycles++;for(let j=i;!seen.has(j);j=a[j])seen.add(j);}return (a.length-cycles)&1;}
function anf(a,n){a=a.slice();for(let j=0;j<n;j++)for(let i=0;i<a.length;i++)if(i&(1<<j))a[i]^=a[i^(1<<j)];return a;}
let rows=[];
for(let n=4;n<=12;n++){
 const g=gates(n),N=1<<n,im=Array.from({length:N},(_,z)=>U(z,g));
 ok(g.length===n-3);ok(new Set(im).size===N);ok(parity(im)===0);
 for(const t of g)ok(parity(Array.from({length:N},(_,z)=>step(z,t)))===0);
 for(let z=0;z<N;z++){let v=im[z];for(let j=g.length-1;j>=0;j--)v=step(v,g[j]);ok(v===z);}
 const bit=im.map(x=>(x>>(n-2))&1),coef=anf(bit,n),top=n===4?3:3+Array.from({length:n-4},(_,i)=>1<<(i+4)).reduce((a,b)=>a+b,0);
 const deg=Math.max(...coef.map((v,i)=>v?i.toString(2).replace(/0/g,'').length:-1));
 ok(deg===n-2);ok(coef[top]===1);ok(coef.filter((v,i)=>v&&i.toString(2).replace(/0/g,'').length===n-2).length===1);
 ok(bit.reduce((a,b)=>a+b,0)===N/2);
 rows.push([n,g.length,deg,N/2]);
}
console.log(JSON.stringify({run:584,assertions:checks,rows,model:'public-acceptance-only;finite-algebra;not-WKEM'}));
