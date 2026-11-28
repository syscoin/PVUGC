'use strict';
// Run 638 compact independent diagnostic; finite Gaussian sums are numerical.
const pi=Math.PI, exp=Math.exp, sqrt=Math.sqrt;
let checks=0;
function ok(v,s){checks++;if(!v)throw Error(s)}
function delta(w){const z=exp(-pi*w*w);return 2*z/(1-z)}
function Z(w,c){let a=0;for(let k=-25;k<=25;k++)a+=exp(-pi*((k-c)/w)**2);return a}
const w1=sqrt(5/3),w2=sqrt(3),d1=delta(w1),d2=delta(w2);
const C=w1*(1+d1)*w2*(1+d2);
let rows=[],sumF=0,sumS=0,sumA=0;
for(let x=-12;x<=12;x++)for(let y=-12;y<=12;y++){
 const E=(3*x*x+2*x*y+2*y*y)/5;
 const E2=3/5*(x+y/3)**2+y*y/3;
 ok(Math.abs(E-E2)<1e-12,'LDL quadratic');
 const f=exp(-pi*E),W=Z(w1,-y/3)*Z(w2,0),s=f/W,a=s*W/C;
 ok(W<=C*(1+1e-13),'theta envelope');
 ok(Math.abs(a-f/C)<1e-14,'exact correction');
 rows.push([f,s,a]);sumF+=f;sumS+=s;sumA+=a;
}
let tv=0,maxerr=0;
for(const [f,s,a] of rows){tv+=Math.abs(f/sumF-s/sumS)/2;maxerr=Math.max(maxerr,Math.abs(f/sumF-a/sumA))}
const R=((1+d1)/(1-d1))*((1+d2)/(1-d2));
ok(tv<(R-1)/2+1e-10,'theta TV');ok(maxerr<1e-12,'corrected target law');ok(Math.abs(sumS-1)<1e-9,'finite tail');
ok(sumA/sumS>=(1-d1)/(1+d1)*(1-d2)/(1+d2)-1e-10,'corrected accept');
for(const s of [1,1.25,2,4])for(const c of [0,.1,.5,1.7])for(let k=-Math.floor(3*s);k<=Math.floor(3*s);k++){
 const sp=sqrt(2)*s,M=sp*exp(pi/(4*s*s));
 const erf=x=>{ // CDF via explicit midpoint quadrature only in bounded envelope diagnostic
  const n=2400, h=1/n, a=(k-.5-c)/sp,b=(k+.5-c)/sp;let v=0;
  for(let j=0;j<n;j++){const y=a+(j+.5)*(b-a)*h;v+=exp(-pi*y*y)}
  return v*(b-a)*h;
 };
 const q=erf(); const f=exp(-pi*((k-c)/s)**2);
 ok(f<=M*q*(1+1e-8),'scalar rejection envelope');
}
const m=256,beta=.2*(2*m-1),e=exp(-pi*36),del=2*e/(1-e);
const oldUpper=exp(-beta/2)*(1+del)**m;
ok(oldUpper<7e-23,'old global sampler exponential loss');
const result={run:638,checks,states:rows.length,sequential_tv:tv,theta_tv_bound:(R-1)/2,corrected_max_error:maxerr,corrected_acceptance:sumA/sumS,old_global_acceptance_upper_m256:oldUpper,conditional_only:true};
console.log(JSON.stringify(result,null,2));
