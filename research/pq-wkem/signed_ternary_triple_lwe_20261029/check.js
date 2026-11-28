// Reproducible research checker; no dependencies; no quantum-hardness benchmark.
console.log(JSON.stringify((function runChecker(){
 let assertions=0, seed=20261029>>>0;
 const ok=(v,msg)=>{assertions++;if(!v)throw Error(msg);};
 const rnd=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;};
 const ri=n=>rnd()%n, mod=(x,q)=>(x%q+q)%q;
 const coin=(m,w)=>{
   let pos=Array.from({length:m},(_,i)=>i),r=Array(m).fill(0);
   for(let k=0;k<w;k++){let j=k+ri(m-k),tmp=pos[k];pos[k]=pos[j];pos[j]=tmp;r[pos[k]]=(rnd()&1)?1:-1;}
   ok(r.reduce((a,x)=>a+Math.abs(x),0)===w,"signed constant weight");
   return r;
 };
 const q=1009,n=2,m=17,B=1,N=4,J=2,w=4,g=Math.floor(q/8);
 ok(g>2*N*w*B,"eight-center margin");
 const A0=Array.from({length:m},()=>ri(q)),A=[A0,A0.map(x=>3*x%q)];
 const s=[ri(q),ri(q)],s2=[mod(s[0]-3,q),mod(s[1]+1,q)];
 const e=Array.from({length:m},()=>ri(3)-1);
 const b=e.map((x,k)=>mod(x+A[0][k]*s[0]+A[1][k]*s[1],q));
 for(let k=0;k<m;k++)ok(mod(b[k]-A[0][k]*s2[0]-A[1][k]*s2[1],q)===mod(e[k],q),"second valid witness");
 const K=Array.from({length:32},()=>ri(256)),bits=[];
 for(let byte of K)for(let k=0;k<8;k++)bits.push((byte>>k)&1);
 let digits=Array.from({length:Math.ceil(bits.length/3)},(_,j)=>(bits[3*j]||0)+2*(bits[3*j+1]||0)+4*(bits[3*j+2]||0));
 ok(digits.length===86,"three-bit packing");let maxnoise=0;
 const distance=(x,y,p)=>Math.min(mod(x-y,p),mod(y-x,p));
 for(let j=0;j<J;j++){
   const decoded=[];
   for(let digit of digits){
     let zs=Array.from({length:N-1},()=>ri(q));
     zs.push(mod(digit-zs.reduce((a,v)=>a+v,0),q));
     ok(mod(zs.reduce((a,v)=>a+v,0),q)===digit,"native digit shares");
     const Cs=zs.map(z=>{
       let r=coin(m,w),u=A.map(row=>mod(row.reduce((sum,x,k)=>sum+x*r[k],0),q));
       let v=mod(b.reduce((sum,x,k)=>sum+x*r[k],0)+g*z,q);
       ok(mod(v-b.reduce((sum,x,k)=>sum+x*r[k],0)-g*z,q)===0,"individual encryption and coins");
       return {r,u,v,z};
     });
     let u=Array.from({length:n},(_,i)=>mod(Cs.reduce((sum,C)=>sum+C.u[i],0),q));
     let v=mod(Cs.reduce((sum,C)=>sum+C.v,0),q);
     let totalr=Array.from({length:m},(_,k)=>Cs.reduce((sum,C)=>sum+C.r[k],0));
     let noise=e.reduce((sum,x,k)=>sum+x*totalr[k],0);
     maxnoise=Math.max(maxnoise,Math.abs(noise));
     ok(Math.abs(noise)<=N*w*B,"all coins bounded for all witnesses");
     let guesses=[];
     for(let witness of [s,s2]){
       let d=mod(v-u.reduce((sum,x,i)=>sum+x*witness[i],0),q);
       ok(d===mod(g*digit+noise,q),"full residual identity");
       let guess=0;for(let a=1;a<8;a++)if(distance(d,g*a,q)<distance(d,g*guess,q))guess=a;
       ok(guess===digit,"same digit for distinct source witnesses");
       guesses.push(guess);
     }
     ok(guesses[0]===guesses[1],"witness independence");
     decoded.push(guesses[0]);
   }
   const decbits=decoded.flatMap(d=>[d&1,(d>>1)&1,(d>>2)&1]);
   ok(decbits.length===258&&decbits[256]===0&&decbits[257]===0,"zero padded bits");
   for(let i=0;i<256;i++)ok(decbits[i]===bits[i],"whole native mock key recovered");
 }
 const q0=3,m0=4,T=[];
 for(let a=0;a<m0;a++)for(let b0=a+1;b0<m0;b0++)for(let sa of [-1,1])for(let sb of [-1,1]){
   let r=[0,0,0,0];r[a]=sa;r[b0]=sb;T.push(r);
 }
 ok(T.length===24,"exact ternary support");
 let collisions=0,tv=0,shift=0;
 for(let h=0;h<6561;h++){
   let x=h,H=[[],[]];for(let i=0;i<2;i++)for(let k=0;k<m0;k++){H[i].push(x%3);x=Math.floor(x/3);}
   const hash=r=>H.map(row=>mod(row.reduce((sum,a,k)=>sum+a*r[k],0),3));
   let counts=Array(9).fill(0);
   for(let r of T){let z=hash(r);counts[3*z[0]+z[1]]++;}
   for(let i=0;i<9;i++){
     tv+=Math.abs(counts[i]/24-1/9)/2;
     let j=3*Math.floor(i/3)+mod(i%3-1,3);
     shift+=Math.abs(counts[i]-counts[j])/(2*24);
   }
   let c=hash(T[0]),d=hash(T[1]);
   if(c[0]===d[0]&&c[1]===d[1])collisions++;
 }
 tv/=6561;shift/=6561;
 const delta0=.5*Math.sqrt(8/24);
 ok(collisions===729,"exact pairwise universality");
 ok(tv<=delta0+1e-12&&shift<=2*delta0+1e-12,"full-ciphertext statistical distance");
 const Q=16777213,nn=256,mm=6800,WW=2000,NN=4,BB=128,JJ=2,L=86;
 let prime=true;for(let k=2;k*k<=Q;k++)if(Q%k===0)prime=false;
 ok(prime,"illustrative q prime");
 let logT=WW;for(let i=1;i<=WW;i++)logT+=Math.log2(mm-i+1)-Math.log2(i);
 const G=Math.floor(Q/8),maxerror=NN*WW*BB;
 ok(G>2*maxerror,"concrete deterministic 3-bit margin");
 const loghash=(nn+1)*Math.log2(Q);
 const newlog=Math.log2(2*JJ*L)-1+(loghash-logT)/2;
 const oldlog=Math.log2(2*JJ*128)-1+(loghash-mm)/2;
 ok(logT>mm && newlog<oldlog && newlog< -128,"statistical support improves");
 const newbytes=L*(nn+1)*3,oldbytes=128*(nn+1)*3;
 ok(newbytes===66306&&oldbytes===98688,"exact packed ciphertext sizes");
 return {status:"PASS",assertions,seed:20261029,toy:{q,n,m,B,N,J,weight:w,digits:digits.length,key_bits:256,distinct_source_witnesses:2,max_observed_noise:maxnoise},exhaustive:{q:q0,m:m0,coin_support:24,hash_matrices:6561,colliding_matrices:collisions,mean_full_tv:+tv.toFixed(9),mean_shift_tv:+shift.toFixed(9),second_moment_delta:+delta0.toFixed(9)},illustrative:{q:Q,n:nn,m:mm,N:NN,B:BB,J:JJ,weight:WW,g:G,max_error:maxerror,half_center_gap:G/2,log2_coin_support:+logT.toFixed(6),log2_joint_bound_new:+newlog.toFixed(6),log2_joint_bound_previous_binary_approx:+oldlog.toFixed(6),aggregate_bytes_new:newbytes,aggregate_bytes_previous:oldbytes,all_contributors_bytes_new:NN*newbytes},limitation:"Honest TRUE-LWE SOURCE only; no generic ORIGINAL-NP compiler or fixed-FALSE/full-original recovery theorem."};
})(),null,2));
