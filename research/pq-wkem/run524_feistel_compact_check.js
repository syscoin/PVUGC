function run524(){
  function assert(v,msg){if(!v)throw Error(msg)}
  function mul(a,b,n,pol){let z=0,mask=(1<<n)-1;for(let i=0;i<n;i++){if(b&1)z^=a;b>>>=1;a<<=1;if(a&(1<<n))a^=pol;a&=mask}return z}
  function pow(a,e,n,p){let z=1;while(e){if(e&1)z=mul(z,a,n,p);a=mul(a,a,n,p);e=Math.floor(e/2)}return z}
  function inv(a,n,p){return a===0?0:pow(a,Math.pow(2,n)-2,n,p)}
  function f(a,k,n,p){return mul(k[0],inv(a,n,p),n,p)^k[1]}
  function make(n,p,alpha,gamma){const ar=Array.from({length:1<<n},(_,i)=>f(i,[alpha,gamma],n,p));const ia=[];for(let i=0;i<ar.length;i++)ia[ar[i]]=i;return {ar,ia}}
  function forward(L,R,keys,func){let T=L^func[0].ar[R^keys[0]],U=R^func[1].ar[T^keys[1]],V=T^func[2].ar[U^keys[2]];return [U,V]}
  function backward(U,V,keys,func){let T=V^func[2].ar[U^keys[2]],R=U^func[1].ar[T^keys[1]],L=T^func[0].ar[R^keys[0]];return [L,R]}
  let st=0x05241234;function rand(){st^=st<<13;st^=st>>>17;st^=st<<5;return st>>>0}
  const records=[];
  for(const [n,p,alpha] of [[4,0x13,9],[8,0x11b,0x57]]){
    const N=1<<n,func=[make(n,p,alpha,3),make(n,p,5,7),make(n,p,11,13)];
    const groups=new Map();
    let pairs=0,exception=0;
    for(let d=1;d<N;d++){
      let gs=new Map();
      for(let u=0;u<N;u++){let q=func[0].ar[u]^func[0].ar[u^d];assert(q!==0,"injectivity");if(!gs.has(q))gs.set(q,[]);gs.get(q).push(u);pairs++}
      for(const roots of gs.values()){assert(roots.length<=4,"degree");if(roots.length===4)exception++}
      groups.set(d,gs);
    }
    let exact=0,shortlist=0,unique=0,maxLen=0;
    for(let j=0;j<128;j++){
      let keys=[rand()%N,rand()%N,rand()%N];
      let p1=[rand()%N,rand()%N],p2=[rand()%N,rand()%N];if(p2[1]===p1[1])p2[1]^=1;
      let [u1,v1]=forward(...p1,keys,func),[u2,v2]=forward(...p2,keys,func);
      let q=p1[0]^p2[0]^func[1].ia[u1^p1[1]]^func[1].ia[u2^p2[1]],d=p1[1]^p2[1];
      let keysOut=[];
      for(const u of (groups.get(d).get(q)||[])){
        let a=p1[1]^u,t=p1[0]^func[0].ar[p1[1]^a],b=t^func[1].ia[u1^p1[1]],c=u1^func[2].ia[v1^t];
        let cand=[a,b,c];
        if(JSON.stringify(forward(...p1,cand,func))===JSON.stringify([u1,v1])&&JSON.stringify(forward(...p2,cand,func))===JSON.stringify([u2,v2]))keysOut.push(cand);
      }
      assert(keysOut.length>0&&keysOut.length<=4,"list size");
      assert(keysOut.some(k=>k.every((x,i)=>x===keys[i])),"true key missing");
      let target=[rand()%N,rand()%N],ct=forward(...target,keys,func);
      let candidates=keysOut.map(k=>backward(...ct,k,func)[0]);
      assert(candidates.includes(target[0]),"target key missing");
      exact++;shortlist++;maxLen=Math.max(maxLen,keysOut.length);if(keysOut.length===1)unique++;
    }
    records.push({n,polynomial:p,full_difference_pairs:pairs,number_of_four_root_equations:exception,reference_tests:exact,false_target_key_list_successes:shortlist,unique_frame_tests:unique,maximum_key_candidates:maxLen})
  }
  return {run:524,pass:true,model:"3-round inverse-first Feistel, full known opened-reference anchor pairs",records}
}
console.log(JSON.stringify(run524(),null,2));
