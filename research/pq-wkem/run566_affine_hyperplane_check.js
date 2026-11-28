#!/usr/bin/env node
"use strict";
const run566Check = function run566Check(){
  const mod=(x,q)=>((x%q)+q)%q;
  const assert=(cond,msg)=>{if(!cond)throw new Error("run566 check failed: "+msg);tests++};
  const tuples=(q,m)=>{let arr=[[]];for(let j=0;j<m;j++){let next=[];for(let a of arr)for(let v=0;v<q;v++)next.push([...a,v]);arr=next;}return arr};
  const inv=(x,q)=>{for(let i=1;i<q;i++)if(mod(x*i,q)===1)return i;throw new Error("no inverse")};
  const rank=(A,q)=>{if(!A.length)return 0;let b=A.map(z=>z.map(v=>mod(v,q))),n=b.length,m=b[0].length,r=0;for(let c=0;c<m&&r<n;c++){let p=-1;for(let i=r;i<n;i++)if(b[i][c]){p=i;break;}if(p<0)continue;[b[r],b[p]]=[b[p],b[r]];const z=inv(b[r][c],q);for(let j=0;j<m;j++)b[r][j]=mod(b[r][j]*z,q);for(let i=0;i<n;i++)if(i!==r&&b[i][c]){let t=b[i][c];for(let j=0;j<m;j++)b[i][j]=mod(b[i][j]-t*b[r][j],q)}r++;}return r;};
  const affineZero=(S,q,m)=>{if(!S.length)return false;const A=Array.from({length:m},(_,j)=>S.map(s=>s[j]));A.push(S.map(()=>1));const tgt=Array(m).fill(0).concat([1]);return rank(A,q)===rank(A.map((r,i)=>r.concat([tgt[i]])),q)};
  const separator=(S,q,m)=>tuples(q,m).some(l=>S.every(s=>mod(l.reduce((v,t,j)=>v+t*s[j],0),q)===1));
  const mix=(S,a,q)=>{assert(mod(a.reduce((u,v)=>u+v,0),q)===1,"affine coefficients");return S[0].map((_,j)=>mod(S.reduce((v,s,i)=>v+a[i]*s[j],0),q))};
  const pow=(n,e,q)=>{let r=1,b=mod(n,q);while(e){if(e&1)r=mod(r*b,q);b=mod(b*b,q);e=Math.floor(e/2)}return r};
  let tests=0,subsets=0,unsafe=0,safe=0,vectorForges=0,booleanAffineSafe=0,constantForges=0,booleanVectors=0;
  let grids=[];
  for(const [q,m] of [[2,1],[2,2],[2,3],[3,1],[3,2],[5,1]]){
    const vec=tuples(q,m).filter(x=>x.some(v=>v!==0));let num=0;
    for(let mask=0;mask<2**vec.length;mask++){const S=vec.filter((_,i)=>((mask>>i)&1)!==0);let a=affineZero(S,q,m),s=separator(S,q,m);assert(a!==s,`affine dual ${q}/${m}/${mask}`);subsets++;num++;a?unsafe++:safe++;}
    grids.push({q,m,subsets:num});
  }
  for(const q of [2,3,5,7,11]){
    let v1=[1,0],v2=[0,1],v3=[1,1],a=[1,1,q-1];
    assert(v1.some(x=>x!==0)&&v2.some(x=>x!==0)&&v3.some(x=>x!==0),"invalid states");
    assert(JSON.stringify(mix([v1,v2,v3],a,q))===JSON.stringify([0,0]),"vector forgery");
    vectorForges++;
    for(let K=0;K<q;K++)for(let x=0;x<q;x++){
      const encryptedModel=[[K,1,0,x],[K,0,1,x],[K,1,1,x]];
      const bad=mix(encryptedModel,a,q);
      assert(JSON.stringify(bad)===JSON.stringify([K,0,0,x]),"release forgery");
      vectorForges++;
      const flag=mix([[K,1,x],[K,1,x],[K,1,x]],a,q);
      assert(JSON.stringify(flag)===JSON.stringify([K,1,x]),"booleanized affine defense");
      booleanAffineSafe++;
      const shifted=[mod(flag[0],q),mod(flag[1]-1,q),mod(flag[2],q)];
      assert(JSON.stringify(shifted)===JSON.stringify([K,0,x]),"constant-injection forgery");
      constantForges++;
    }
  }
  for(const [q,m] of [[2,3],[3,2],[5,2],[7,2]]){
    for(const v of tuples(q,m)){let product=1;for(const s of v)product=mod(product*(1-pow(s,q-1,q)),q);let bit=mod(1-product,q);assert(bit===(v.some(s=>s!==0)?1:0),"Fermat booleanizer");booleanVectors++;}
  }
  return {run:566,status:"PASS",assertions_passed:tests,subsets_exhausted:subsets,unsafe_subsets:unsafe,safe_subsets:safe,grids,vector_affine_forgery_fixtures:vectorForges,booleanized_affine_only_nonrelease_fixtures:booleanAffineSafe,constant_injection_forgery_fixtures:constantForges,public_boolean_zero_test_vectors:booleanVectors,real_encryption_implemented:false,QPT_security_established:false};
};
console.log(JSON.stringify(run566Check(),null,2));
