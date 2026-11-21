const check = function check(){
  let assertions=0;
  function ok(v,m){if(!v)throw Error(m);assertions++}
  function sphere(m,h){let out=[];function rec(v){if(v.length===m){if(v.reduce((a,b)=>a+Math.abs(b),0)===h)out.push(v);return;}for(let x=-h;x<=h;x++)rec([...v,x])}rec([]);return out}
  function leak(w,k){if(k===0)return"0";if(k===1)return String(+(w[0]<0));if(k===2)return String(+(w[0]<0))+":"+w.slice(1).reduce((a,b)=>a+Math.abs(b),0)%2;return String(+(w[0]<0))+":"+w.slice(1).reduce((a,b)=>a+Math.abs(b),0)%2+":"+ +(w[1]<0)}
  function matrices(q,m){let out=[];function rec(v){if(v.length===m){out.push(v);return;}for(let a=0;a<q;a++)rec([...v,a])}rec([]);return out}
  function add(M,k){M.set(k,(M.get(k)||0)+1)}
  function sourceTV(q,m,h,k,d){
    let W=sphere(m,h),As=matrices(q,m),R=new Map(),H=new Map(),classes=[...new Set(W.map(w=>leak(w,k)))];
    let dot=(a,w)=>((a.reduce((z,x,i)=>z+x*w[i],0)%q)+q)%q;
    for(let a of As)for(let w1 of W){let l1=leak(w1,k),u1=dot(a,w1);
      if(d===1){add(H,JSON.stringify([a,l1]));add(R,JSON.stringify([a,l1,u1]));}
      else for(let w2 of W){let l2=leak(w2,k),u2=dot(a,w2);add(H,JSON.stringify([a,l1,l2]));add(R,JSON.stringify([a,l1,l2,u1,u2]));}
    }
    let sum=0;
    if(d===1)for(let a of As)for(let l of classes){let mass=H.get(JSON.stringify([a,l]))||0;for(let u=0;u<q;u++)sum+=Math.abs(q*(R.get(JSON.stringify([a,l,u]))||0)-mass)}
    else for(let a of As)for(let l1 of classes)for(let l2 of classes){let mass=H.get(JSON.stringify([a,l1,l2]))||0;
      for(let u1=0;u1<q;u1++)for(let u2=0;u2<q;u2++)sum+=Math.abs(q*q*(R.get(JSON.stringify([a,l1,l2,u1,u2]))||0)-mass);
    }
    return {tv:sum/(2*As.length*W.length**d*q**d),classes:classes.length,N:W.length};
  }
  const toy=[];
  for(let k=0;k<4;k++){let v=sourceTV(7,3,2,k,1);let bound=.5*Math.sqrt(6*v.classes/v.N);ok(v.tv<=bound+1e-12,"leak bound");toy.push({bits:k,classes:v.classes,tv:v.tv,bound})}
  let v1=sourceTV(5,2,2,1,1),v2=sourceTV(5,2,2,1,2);ok(v2.tv<=2*v1.tv+1e-12,"common A two sources");
  // Deliberately duplicated columns for CORRECTNESS only, NOT a hardness instance.
  let q=101,g=7,T=Math.floor(q/g),A=[[3,7,3,7],[11,19,11,19]],w1=[1,1,0,0],w2=[0,0,1,1],U=[10,30];
  ok(A.every((r,i)=>r[0]+r[1]===U[i]&&r[2]+r[3]===U[i]),"distinct openings");
  let rng=1729;function rnd(n){rng=(Math.imul(rng,1664525)+1013904223)>>>0;return rng%n}
  function enc(a){let s=[rnd(q),rnd(q)],e=Array.from({length:4},()=>rnd(3)-1),eps=rnd(3)-1;
    return [Array.from({length:4},(_,j)=>(A[0][j]*s[0]+A[1][j]*s[1]+e[j]+q*10)%q),(U[0]*s[0]+U[1]*s[1]+eps+g*a)%q]}
  function dec(ct,w){let r=(ct[1]-ct[0].reduce((z,x,i)=>z+x*w[i],0))%q;r=(r+q*100)%q;let dist=a=>Math.min((r-g*a+q*100)%q,(g*a-r+q*100)%q),win=0;for(let a=1;a<T;a++)if(dist(a)<dist(win))win=a;return win}
  for(let trial=0;trial<60;trial++){
    let K=rnd(65536),r0=rnd(65536),shares=Array.from({length:3},()=>rnd(65536)),D=shares.reduce((a,b)=>a^b,r0),V=K^r0;
    let caps=shares.map(z=>{let digits=[];for(let i=0;i<5;i++){digits.push(z%T);z=Math.floor(z/T)}return digits.map(enc)});
    for(let w of [w1,w2]){let zz=caps.map(ct=>ct.map(c=>dec(c,w)).reverse().reduce((z,a)=>z*T+a,0));ok(zz.every((z,i)=>z===shares[i]),"shares");ok((V^D^zz[0]^zz[1]^zz[2])===K,"same K")}
  }
  function choose(n,k){let z=1n;for(let i=1;i<=k;i++)z=z*BigInt(n-i+1)/BigInt(i);return z}
  function lg(n){let s=n.toString(2),b=Math.min(53,s.length);return s.length-b+Math.log2(parseInt(s.slice(0,b),2))}
  let N=0n;for(let k=1;k<=800;k++)N+=(1n<<BigInt(k))*choose(1600,k)*choose(799,k-1);
  let log2N=lg(N),log2delta0=-1+.5*(lg(65537n**128n-1n)-log2N),stat0=log2delta0+Math.log2(42);
  let maxbits=Math.floor(2*(-128-stat0));ok(maxbits===457,"457 bit leakage budget");
  return {status:"PASS_RESTRICTED_LEAKAGE_NOT_GENERIC_NP",assertions,toy,twoColumnsSharedA:{TV:v2.tv,bound:2*v1.tv},twoDistinctOpeningTrials:60,illustrativeNotQPTCertified:{log2N,log2delta0,log2_t_d_delta0:stat0,maxPerColumnLeakageBits:maxbits,log2_t_d_delta_at_457:stat0+457/2}};
};
console.log(JSON.stringify(check(),null,2));
