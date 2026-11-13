'use strict';
let assertions=0;
function ok(b){assertions++;if(!b)throw Error('failed '+assertions)}
function F(q,a,n){if(a<n)return 0;let v=1;for(let j=0;j<n;j++)v*=1-q**(j-a);return v}
function isSing2(U,V,q,R){let [a,b,c,d]=[0,0,0,0];for(let i=0;i<R;i++){a+=U[i]*V[2*i];b+=U[i]*V[2*i+1];c+=U[R+i]*V[2*i];d+=U[R+i]*V[2*i+1]}return ((a*d-b*c)%q+q)%q===0}
function vectors(q,n){let list=[];for(let i=0;i<q**n;i++){let x=i,v=[];for(let j=0;j<n;j++){v.push(x%q);x=Math.floor(x/q)}list.push(v)}return list}
const cases=[];
for(let [q,N,R] of [[2,2,2],[2,2,3],[3,1,2]]){
 let count=0,total=0,us=vectors(q,N*R),vs=vectors(q,N*R);
 for(let u of us)for(let v of vs){let sing=N===2?isSing2(u,v,q,R):u.reduce((a,t,i)=>a+t*v[i],0)%q===0;count+=Number(sing);total++}
 let p=1-F(q,R,N)*F(q,N,N);ok(Math.abs(count/total-p)<1e-13);
 for(let s=1;s<=5;s++){ok(p**s<=p+1e-15);ok(p**s>=0)}
 cases.push({q,N,R,counts:[count,total],singular:p})
}
const q=257,ell=2,b=1,m=2,kappa=128,N=2*b*m+1;
const pmax=(1+q**(-(2*b-1)))/(q-1);
const s=Math.ceil((kappa+ell*Math.log2(q))/-Math.log2(pmax));
ok(ell*Math.log2(q)+s*Math.log2(pmax)<=-kappa+1e-10);
ok(ell*Math.log2(q)+(s-1)*Math.log2(pmax)>-kappa-1e-10);
console.log(JSON.stringify({run:662,assertions,cases,example:{field:q,variables:ell,copies:s,N,log2_union_bound:ell*Math.log2(q)+s*Math.log2(pmax)},claim:'bounded explicit-field-input soundness only; key hiding unproved'}));
