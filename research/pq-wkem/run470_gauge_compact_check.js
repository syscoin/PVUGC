(()=>{"use strict";
let checks=0;const ok=(v,m)=>{checks++;if(!v)throw Error(m)};
const I=[[1,0],[0,1]], mod=(x,q)=>(x%q+q)%q;
const M=(a,b,q)=>Array.from({length:2},(_,i)=>Array.from({length:2},(_,j)=>mod(a[i][0]*b[0][j]+a[i][1]*b[1][j],q)));
const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const inv=(a,q)=>{let d=mod(a[0][0]*a[1][1]-a[0][1]*a[1][0],q);ok(d!==0,"singular");let x=1;while(mod(d*x,q)!==1)x++;return [[mod(a[1][1]*x,q),mod(-a[0][1]*x,q)],[mod(-a[1][0]*x,q),mod(a[0][0]*x,q)]]};
const prod=(xs,q)=>xs.reduce((a,b)=>M(a,b,q),I);
function kernel(U,A,V,C,q){
 let rows=[];for(const [L,R] of [[U,A],[V,C]])for(let i=0;i<2;i++)for(let j=0;j<2;j++){
  let row=[];for(let k=0;k<4;k++){let E=[[0,0],[0,0]];E[k>>1][k&1]=1;row.push(mod(M(L,E,q)[i][j]-M(E,R,q)[i][j],q))}rows.push(row)}
 let piv=[],r=0;for(let col=0;col<4;col++){let k=r;while(k<rows.length&&!rows[k][col])k++;if(k===rows.length)continue;
 [rows[r],rows[k]]=[rows[k],rows[r]];let z=1;while(mod(rows[r][col]*z,q)!==1)z++;rows[r]=rows[r].map(v=>mod(v*z,q));
 for(let t=0;t<rows.length;t++)if(t!==r){let f=rows[t][col];rows[t]=rows[t].map((v,h)=>mod(v-f*rows[r][h],q))}piv.push(col);r++}
 let free=[0,1,2,3].filter(i=>!piv.includes(i));ok(free.length===1,"intertwiner nullity");let v=[0,0,0,0];v[free[0]]=1;
 piv.forEach((p,i)=>{v[p]=mod(-rows[i][free[0]],q)});return [[v[0],v[1]],[v[2],v[3]]]
}
let fixtures=0;
for(const q of [7,11])for(let seed=1;seed<=8;seed++){
 const A=[[1,1],[0,1]],C=[[1,0],[1,1]],D=[[1,2],[0,1]];
 const B=[[I,A],[C,I],[I,D],[I,inv(D,q)]], T=prod([A,C],q), F=[[3,1],[1,1]];
 const Q=Array.from({length:5},(_,i)=>{let a=mod(seed*(i+3)+4,q),b=mod(seed*(2*i+7)+5,q);return [[1,a],[b,mod(1+a*b,q)]]});
 const pub=B.map((pair,i)=>pair.map(b=>M(M(Q[i],b,q),inv(Q[i+1],q),q)));
 const U=M(inv(pub[0][0],q),pub[0][1],q),V=M(pub[1][0],inv(pub[1][1],q),q);
 let h=[null,kernel(U,A,V,C,q),null,null,null];h[0]=M(pub[0][0],h[1],q);
 for(let i=1;i<4;i++)h[i+1]=M(M(inv(pub[i][0],q),h[i],q),B[i][0],q);
 for(let i=0;i<4;i++)for(let b=0;b<2;b++)ok(eq(M(M(h[i],B[i][b],q),inv(h[i+1],q),q),pub[i][b]),"reconstruct all public views");
 let ct=0,cf=0;for(let word=0;word<16;word++){
 let bs=Array.from({length:4},(_,i)=>(word>>(3-i))&1);let raw=prod(bs.map((v,i)=>B[i][v]),q);
 if(eq(raw,T))ct++;if(eq(raw,F))cf++}
 ok(ct===2&&cf===0,"source witness census");
 for(let target of [T,F])ok(eq(M(M(h[0],target,q),inv(h[4],q),q),M(M(Q[0],target,q),inv(Q[4],q),q)),"secret target recovered");
 fixtures++
}
const out={run:470,fixtures,fields:[7,11],true_witnesses_per_fixture:2,false_witnesses_per_fixture:0,all_secret_targets_recovered:true,checks};
if(typeof console!=="undefined")console.log(JSON.stringify(out));return JSON.stringify(out);
})()
