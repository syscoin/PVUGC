'use strict';
/* MINK-DENSE standalone exact reference checker. Node 18+, no packages.
   Toy algebra and statistical enumeration; NOT a PQ-hardness experiment. */
let checks=0;
function chk(x,msg){checks++;if(!x)throw Error(msg||'check failed')}
function mod(x,q){return ((x%q)+q)%q}
const q=257,n=3,m=40,g=(q-1)/2;
let A=Array.from({length:m},(_,i)=>Array.from({length:n},(_,j)=>(17*i+23*j+7)%q));
let bc=Array.from({length:m},(_,i)=>(29*i+11)%q);
let s=[3,7,11], e=Array.from({length:m},(_,i)=>(i%3)-1);
let bL=A.map((row,i)=>mod(row.reduce((v,x,j)=>v+x*s[j],0)+e[i],q));
function enc(b,mu,k){
 let r=Array.from({length:m},(_,i)=>((17*i+11*k+13*mu)%7<3)?1:0);
 let u=Array.from({length:n},(_,j)=>mod(A.reduce((v,row,i)=>v+row[j]*r[i],0),q));
 let v=mod(b.reduce((v,x,i)=>v+x*r[i],0)+g*mu,q);
 return {u,v,r,mu}
}
function opened(b,c){
 let u=Array.from({length:n},(_,j)=>mod(A.reduce((v,row,i)=>v+row[j]*c.r[i],0),q));
 let v=mod(b.reduce((v,x,i)=>v+x*c.r[i],0)+g*c.mu,q);
 return c.r.every(z=>z===0||z===1)&&c.u.every((z,j)=>z===u[j])&&c.v===v;
}
function dec(c){let t=mod(c.v-c.u.reduce((v,x,j)=>v+x*s[j],0),q);
 return Math.min(t,q-t)<Math.min(mod(t-g,q),mod(g-t,q))?0:1;
}
for(let k=0;k<128;k++){
 let bit=k%2,real=enc(bc,bit,k),hybrid=enc(bL,bit,k+1);
 chk(opened(bc,real),'uniform-CRS exact opening');
 chk(!opened(bc,{...real,mu:1-bit}),'same coins cannot open other bit');
 chk(opened(bL,hybrid)&&dec(hybrid)===bit,'LWE-key hybrid honest decoding');
}
let k4=0;
const E=[[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]];
for(let w=0;w<81;w++){
 let z=w,col=Array.from({length:4},()=>{let a=z%3;z=Math.floor(z/3);return a});
 let good=E.filter(([u,v])=>col[u]!==col[v]).length;
 chk(good<=5,'K4 false soundness');k4+=good;
}
let sum=0,max=0;
for(let key=0;key<59049;key++){
 let z=key,M=[],B=[];
 for(let i=0;i<5;i++){M.push(z%3);z=Math.floor(z/3)}
 for(let i=0;i<5;i++){B.push(z%3);z=Math.floor(z/3)}
 let hist=Array(9).fill(0);
 for(let r=0;r<32;r++){
  let u=0,v=0;for(let i=0;i<5;i++)if((r>>>i)&1){u=(u+M[i])%3;v=(v+B[i])%3}
  hist[3*u+v]++;
 }
 let tv=.5*hist.reduce((a,c)=>a+Math.abs(c/32-1/9),0);
 sum+=tv;if(tv>max)max=tv;
}
let mean=sum/59049,bound=.5*Math.sqrt(9/32);
chk(mean<bound,'averaged leftover-hash lemma');
chk(max>bound,'the average-key theorem is NOT an every-key theorem');
let log2eps=-1+.5*(257*Math.log2(65537)-4800);
chk(4*4800*3<65536,'illustrative correctness noise condition');
chk(log2eps< -256,'illustrative leftover slack, NOT LWE hardness');
chk(3*(4800*256+2*4800)===3715200,'shared-A size');
console.log(JSON.stringify({run:'MINK-DENSE-2026-11-01-T19',checks,k4_assignments:81,k4_valid_edge_sum:k4,lhl_key_space:59049,lhl_mean_tv:mean,lhl_max_tv:max,lhl_bound:bound,illustrative_log2_eps:log2eps,shared_key_bytes:3715200,success:true},null,2));
