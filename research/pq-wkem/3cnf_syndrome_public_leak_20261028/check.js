const run = function run(){
 let count=0;const ok=x=>{count++;if(!x)throw Error("assertion "+count)};
 const mod=(x,q)=>(x%q+q)%q;
 function source(n,clauses){let A=[],b=[];for(let i=0;i<n;i++){let r=Array(n).fill(0);r[i]=1;A.push([...r],[...r]);b.push(0,1)}for(let c0 of clauses){let c=[...c0];while(c.length<3)c.push(c0[c0.length-1]);let r=Array(n).fill(0),neg=0;for(let l of c)if(l>0)r[l-1]++;else{r[-l-1]--;neg++}A.push(r);b.push(2-neg)}return{A,b}}
 function opens(A,b,s,q){return A.every((r,i)=>{let e=mod(b[i]-r.reduce((v,x,j)=>v+x*s[j],0),q);return e===0||e===1||e===q-1})}
 function truth(cs,s){return cs.every(c=>c.some(l=>l>0?s[l-1]===1:s[-l-1]===0))}
 const cs=[[1,2,2]],F=[[1,1,1],[-1,-1,-1]],{A,b}=source(2,cs),{A:Af,b:bf}=source(1,F);
 let witnesses=[];for(let x=0;x<17;x++)for(let y=0;y<17;y++){let s=[x,y],v=opens(A,b,s,17),t=(x<=1&&y<=1&&truth(cs,s));ok(v===t);if(v)witnesses.push(s)}
 for(let x=0;x<17;x++)ok(!opens(Af,bf,[x],17));
 ok(witnesses.length===3&&[...b,...bf].every(x=>Math.abs(x)<=2));
 const q=257,h=4,g=9,B=28,ell=5,K=0x123456,Z=[0x345678,0xabcdee],U0=0x112233,D=U0^Z[0]^Z[1],V=K^U0;
 const digits=v=>{let a=[];for(let i=0;i<ell;i++){a.push(v%B);v=Math.floor(v/B)}ok(v===0);return a};
 const enc=(A,b,r,a,g,q)=>({c:A[0].map((_,j)=>mod(A.reduce((v,row,i)=>v+row[j]*r[i],0),q)),d:mod(b.reduce((v,x,i)=>v+x*r[i],g*a),q)});
 const decode=(v,g,B,q)=>{let best=0,dist=q;for(let a=0;a<B;a++){let d=mod(v-g*a,q);d=Math.min(d,q-d);if(d<dist){dist=d;best=a}}return best};
 let caps=Z.map((s,i)=>digits(s).map((a,j)=>{let r=Array(b.length).fill(0);for(let k=0;k<h;k++)r[(k+i+j)%r.length]=(k+i+j)%2?-1:1;return enc(A,b,r,a,g,q)}));
 for(let w of witnesses){let got=caps.map(cap=>cap.map(({c,d})=>decode(mod(d-c.reduce((v,x,j)=>v+x*w[j],0),q),g,B,q)).reduceRight((v,x)=>v*B+x,0));ok(got[0]===Z[0]&&got[1]===Z[1]);ok((V^D^got[0]^got[1])===K)}
 const m=2000,H=800,Q=65537,G=1601,R=Math.floor(Q/G),L=147,largeB=bf.concat(Array(m-bf.length).fill(0));
 for(let a=0;a<30;a++){let r=Array(m).fill(0);for(let k=0;k<H;k++)r[(a+1171*k)%m]=(a+k)%2?1:-1;let d=mod(largeB.reduce((v,x,i)=>v+x*r[i],G*(a%R)),Q);ok(decode(d,G,R,Q)===a%R)}
 function choose(n,k){let v=1n;for(let i=1;i<=k;i++)v=v*BigInt(n-k+i)/BigInt(i);return v}
 const N=choose(m,H)*(1n<<800n),Qspace=65537n**129n;
 ok(4n*N>BigInt(L*L)*(Qspace-1n)*(1n<<256n));
 // General dense, non-diagonal invertible public basis; variable rows expose affine offset.
 const T=[[2,3],[5,7]],z=[119,231],Aprime=A.map(r=>T[0].map((_,j)=>mod(r.reduce((v,x,k)=>v+x*T[k][j],0),Q)));
 const bprime=b.map((v,i)=>mod(v+Aprime[i].reduce((a,x,k)=>a+x*z[k],0),Q));
 let det=mod(Aprime[0][0]*Aprime[2][1]-Aprime[0][1]*Aprime[2][0],Q);
 const pow=(a,n)=>{let v=1;while(n){if(n%2)v=v*a%Q;a=a*a%Q;n=Math.floor(n/2)}return v};
 let inv=pow(det,Q-2),zr=[mod(inv*(bprime[0]*Aprime[2][1]-bprime[2]*Aprime[0][1]),Q),mod(inv*(Aprime[0][0]*bprime[2]-Aprime[2][0]*bprime[0]),Q)];
 ok(zr.every((v,i)=>v===z[i]));
 for(let t=0;t<30;t++){let r=Array(b.length).fill(0);for(let k=0;k<4;k++)r[(t+k)%r.length]=(t+k)%2?-1:1;let e1=enc(A,b,r,t,41,Q),e2=enc(Aprime,bprime,r,t,41,Q);
 ok(mod(e2.d-e2.c.reduce((v,x,j)=>v+x*zr[j],0),Q)===e1.d)}
 return {status:"PASS; candidate proven INSECURE",checks:count,exact_original_source_soundness:true,all_valid_original_same_mock_capability:true,false_source_direct_rounding_attack:true,affine_offset_publicly_recovered:true,illustrative:{q:65537,n:128,m:2000,h:800,radix:40,columns:147},uniform_H_only_bound_below_2_minus_128:true,log2_upper_bound_on_attack_failure:Math.log2(2*L)-H/8/Math.LN2,qpt_security_claim:"NONE"};
};
console.log(JSON.stringify(run(),null,2));
