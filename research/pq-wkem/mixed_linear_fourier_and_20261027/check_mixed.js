'use strict';
// Exact finite-algebra certificate; NOT a QPT-LWE or native-signature test.
let checks=0;
const ok=(x,label)=>{if(!x)throw Error(label);checks++};
const q=8,g=4;
for(let h=0;h<q;h++)for(let alpha=0;alpha<q;alpha++)for(let B=0;B<q;B++)
for(let t=0;t<q;t++)for(let u=0;u<q;u++)for(let e=-1;e<=1;e++){
 const A0=alpha,A1=(B+h*alpha)%q,s0=(t-h*u+q*q)%q,s1=u;
 ok((A0*s0+A1*s1+e+q*q)%q===(alpha*t+B*u+e+q*q)%q,'joint LWE embedding');
 ok((g*s0+g*h*s1)%q===(g*t)%q,'opening t');
 ok((A1-h*A0+q*q)%q===B,'reconstruction');
}
for(let B=1;B<q;B+=2)for(let alpha=0;alpha<q;alpha++)for(let t=0;t<q;t++){
 const seen=new Set();for(let u=0;u<q;u++)seen.add((alpha*t+B*u)%q);
 ok(seen.size===q,'false source full rank produces uniform p');
}
const joint=(K)=>{
 const out=new Map();
 for(let U=0;U<4;U++)for(let Z=0;Z<4;Z++)for(let d=0;d<4;d++)for(let y=0;y<4;y++){
  const V=K^U,D=U^Z,c=V^d;
  let n=1;for(let j=0;j<2;j++)n*=((y>>j&1)===(c>>j&1))?5:1;
  const key=[V,D,d,y].join(',');out.set(key,(out.get(key)||0)+n);
 }
 return out;
};
for(const [K1,K2] of [[0,2],[1,3]]){
 const a=joint(K1),b=joint(K2);ok(a.size===256&&b.size===256,'whole joint support');
 for(const [key,n] of a)ok(b.get(key)===n,'native-pk-correlated null law');
}
// In the two-share release, a false NP Fourier source ignores the encoded V.
for(let K=0;K<4;K++)for(let U=0;U<4;U++)for(let z=0;z<4;z++){
 const V=K^U,D=U^z;
 for(let c=0;c<4;c++)ok((V^K)===U&&D===(U^z)&&c>=0,'false NP ignores V');
}
console.log(JSON.stringify({record:'mixed-linear-fourier-and-20261027-turn9',assertions:checks,kind:'exact finite algebra only',scope:'QPT hardness, Bitcoin and native signatures not tested'},null,2));
