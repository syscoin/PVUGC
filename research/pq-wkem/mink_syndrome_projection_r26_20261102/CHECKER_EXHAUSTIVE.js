function runR26Exhaustive(){
  const q=3;let checks=0,matrices=0;
  const mod=x=>((x%q)+q)%q,ck=(x,s)=>{checks++;if(!x)throw Error("R26 exhaustive: "+s);};
  const vectors=n=>Array.from({length:q**n},(_,v)=>{const a=[];for(let i=0;i<n;i++){a.push(v%q);v=Math.floor(v/q);}return a;});
  const rs=vectors(2),zs=vectors(3),key=x=>x.join(",");
  const dot=(a,b)=>mod(a.reduce((s,x,i)=>s+x*b[i],0));
  const add=(a,b)=>a.map((x,i)=>mod(x+b[i]));
  for(let code=0;code<q**6;code++){
    let v=code;
    const B=Array.from({length:3},()=>Array.from({length:2},()=>{const x=v%q;v=Math.floor(v/q);return x;}));
    const image=rs.map(r=>B.map(row=>dot(row,r)));
    const spanSize=new Set(image.map(key)).size;
    const rank={1:0,3:1,9:2}[spanSize];
    ck(rank!==undefined,"column span");
    const left=zs.filter(l=>[0,1].every(j=>mod(l.reduce((s,x,i)=>s+x*B[i][j],0))===0));
    ck(left.length===q**(3-rank),"left kernel dimension");
    let H=[],basisSpan=new Set([key([0,0,0])]);
    for(const h of left){
      if(basisSpan.has(key(h)))continue;
      H.push(h);
      const next=new Set();
      for(const a of vectors(H.length)){
        let z=[0,0,0];
        for(let i=0;i<H.length;i++)z=add(z,H[i].map(x=>mod(x*a[i])));
        next.add(key(z));
      }
      basisSpan=next;
    }
    ck(H.length===3-rank&&basisSpan.size===left.length,"complete nullspace basis");
    const err=[1,0,2],syn=x=>H.map(h=>dot(h,x));
    for(let mu=0;mu<2;mu++){
      const offset=add(err,[mu,0,0]),actual=image.map(x=>add(x,offset));
      const target=key(syn(offset));
      const fiber=zs.filter(x=>key(syn(x))===target);
      ck(fiber.length===q**rank,"exact affine fiber");
      const freq=new Map();
      for(const x of actual)freq.set(key(x),(freq.get(key(x))||0)+1);
      ck(freq.size===fiber.length,"fiber support");
      for(const x of fiber)ck(freq.get(key(x))===q**(2-rank),"uniform conditional distribution");
      for(const l of left)for(const x of actual)ck(dot(l,x)===dot(l,offset),"all valid extraction functionals");
    }
    matrices++;
  }
  return {run:"MINK-SYNDROME-PROJECTION-R26-EXHAUSTIVE",q,matrices,checks,pass:true};
}
console.log(JSON.stringify(runR26Exhaustive(),null,2));
