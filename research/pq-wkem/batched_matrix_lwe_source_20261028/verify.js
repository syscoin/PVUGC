"use strict";
let checks=0;
function ok(cond,why){checks++;if(!cond)throw Error("failed: "+why);}
const q=257,n=2,d=3,m=6,h=3,g=2*h+1,radix=Math.floor(q/g);
const A=Array.from({length:m},(_,i)=>[i+1,2*(i+1)]);
const S=[[13,17,23],[19,29,31]];
const E=Array.from({length:m},(_,i)=>Array.from({length:d},(_,j)=>(i+j)%3-1));
const B=Array.from({length:m},(_,i)=>Array.from({length:d},(_,j)=>(A[i][0]*S[0][j]+A[i][1]*S[1][j]+E[i][j])%q));
const S2=[[11,15,21],[20,30,32]];
function valid(T){return A.every((row,i)=>B[i].every((z,j)=>((row[0]*T[0][j]+row[1]*T[1][j]+E[i][j]-z)%q+q)%q===0));}
ok(valid(S)&&valid(S2)&&JSON.stringify(S)!==JSON.stringify(S2),"two genuine source witnesses");
const coins=[[1,-1,1,0,0,0],[-1,1,0,-1,0,0],[0,1,-1,0,1,0]];
for(const r of coins){
  ok(r.reduce((v,x)=>v+Math.abs(x),0)===h,"l1 sphere");
  const c=Array.from({length:n},(_,j)=>((A.reduce((v,row,i)=>v+r[i]*row[j],0)%q)+q)%q);
  for(let a0=0;a0<11;a0++)for(let a1=0;a1<11;a1++)for(let a2=0;a2<11;a2++){
    const a=[a0,a1,a2];
    const v=Array.from({length:d},(_,j)=>((B.reduce((v,row,i)=>v+r[i]*row[j],0)+g*a[j])%q+q)%q);
    for(const T of [S,S2])for(let j=0;j<d;j++){
      const y=((v[j]-c.reduce((sum,cj,k)=>sum+cj*T[k][j],0))%q+q)%q;
      let best=-1,dist=q;
      for(let b=0;b<radix;b++){
        const gap=((y-g*b)%q+q)%q;
        const cyc=Math.min(gap,q-gap);
        if(cyc<dist){dist=cyc;best=b;}
      }
      ok(best===a[j]&&dist<=h,"every-original-witness batched recovery");
    }
  }
}
function comb(a,b){let v=1n;for(let i=1;i<=b;i++)v=v*BigInt(a-i+1)/BigInt(i);return v;}
function sphere(m,h){let value=0n;for(let k=1;k<=Math.min(m,h);k++)value+=(1n<<BigInt(k))*comb(m,k)*comb(h-1,k-1);return value;}
let pairs=[0,0,0,0,0,0],rs=[[1,0],[-1,0],[0,1],[0,-1]];
for(let ix=0;ix<15625;ix++){
  let x=ix,H=[[],[]];for(let i=0;i<2;i++)for(let j=0;j<3;j++){H[i].push(x%5);x=Math.floor(x/5);}
  const hashes=rs.map(r=>Array.from({length:3},(_,j)=>(r[0]*H[0][j]+r[1]*H[1][j]+10)%5));
  let z=0;for(let i=0;i<4;i++)for(let j=i+1;j<4;j++){if(hashes[i].every((a,k)=>a===hashes[j][k]))pairs[z]++;z++;}
}
ok(pairs.every(x=>x===125),"exact q^-3 collision for every pair");
const Nnew=sphere(1600,800),Nold=sphere(1600,696),Q=65537n;
const newBatch=4,oldDigits=47,t=3,nd=142;
ok((BigInt(t*newBatch)**2n)*(Q**BigInt(nd)-1n)*(1n<<256n)<=4n*Nnew,"128bit statistical bound");
ok((BigInt(t*newBatch)**2n)*(Q**BigInt(nd)-1n)*Nold<(BigInt(t*oldDigits)**2n)*(Q**129n-1n)*Nnew,"strictly stronger than predecessor statistical loss");
const oldCT=t*oldDigits*129,newCT=t*newBatch*nd;
ok(oldCT===18189&&newCT===1704,"ciphertext counts");
ok(1600*129+oldCT<1600*(128+14)+newCT,"one native capability has higher total size");
ok(1600*129+2*oldCT>1600*(128+14)+2*newCT,"two same-predicate capabilities amortize public key");
return JSON.stringify({status:"PASS",assertions:checks,small_H_matrices:15625,collisions_per_sphere_pair:pairs,toy_distinct_SOURCE_witnesses:2,toy_batched_digit_trials:3*11**3,old_ciphertext_field_elements:oldCT,new_ciphertext_field_elements:newCT,old_full_view_elements_one:1600*129+oldCT,new_full_view_elements_one:1600*142+newCT,old_full_view_elements_two:1600*129+2*oldCT,new_full_view_elements_two:1600*142+2*newCT,statistical_term_stronger:true,not_proven:"generic NP or 128bit QPT hardness"},null,2)+"\n";