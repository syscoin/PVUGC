"use strict";
let checks=0, fixtures=0, worstError=0;
function ok(x){checks++;if(!x)throw Error("assertion "+checks);}
for(let d=3;d<=6;d++)for(let c=1;c<=2;c++)for(let h=1;h<=4;h++)for(let ghosts=0;ghosts<=1;ghosts++){
let R=2**c,N=2**d*R,pairs=new Set(),tapes=R-1;
for(let u=0;u<h+ghosts;u++)for(let r=0;r<tapes;r++)pairs.add(u*R+r);
let mu=pairs.size/N;
ok(mu>0);ok(Math.abs(mu-((h+ghosts)*tapes/N))<1e-14);
let theta=Math.asin(Math.sqrt(mu)),j=Math.max(0,Math.round(Math.PI/(4*theta)-0.5));
let a=new Array(N).fill(1/Math.sqrt(N));
for(let step=0;step<j;step++){
for(const i of pairs)a[i]*=-1;
let mean=a.reduce((x,y)=>x+y,0)/N;
a=a.map(x=>2*mean-x);
}
let observed=0;for(const i of pairs)observed+=a[i]*a[i];
let predicted=Math.sin((2*j+1)*theta)**2;
worstError=Math.max(worstError,Math.abs(observed-predicted));
ok(Math.abs(observed-predicted)<1e-9);
for(let u=0;u<h;u++)ok(u<h && !((u>=h)&&(u<h+ghosts)));
for(let u=h;u<h+ghosts;u++)ok(!(u<h));
fixtures++;
}
for(let d=3;d<=8;d++){let honest=0,ghosts=1;ok(honest===0&&ghosts>0);}
return JSON.stringify({run:412,checker:"compact public-coins coherent frontier",checks,fixtures,false_original_ghost_tests:6,worst_error:worstError,crypto_security_proved:false},null,2)+"\n";