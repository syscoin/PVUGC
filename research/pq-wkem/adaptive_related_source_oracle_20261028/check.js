const runChecks = function runChecks(){
  let checks=0;
  const assert=(b,m)=>{checks++;if(!b)throw Error(m)};
  let seed=0x20261028>>>0;
  const rand=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0};
  const mod=(x,q)=>((x%q)+q)%q;
  const q=257,n=2,m=6,d=2,h=2,g=7,t=3,base=Math.floor(q/g),bits=24;
  const A=Array.from({length:n},()=>Array.from({length:m},()=>rand()%q));
  for(let i=0;i<n;i++)A[i][1]=A[i][0];
  const W=[[1,0],[0,0],[1,0],[0,1],[0,-1],[0,0]];
  const Wp=[[0,0],[1,0],[1,0],[0,1],[0,-1],[0,0]];
  const multiply=W=>Array.from({length:n},(_,i)=>Array.from({length:d},(_,j)=>mod(W.reduce((s,row,k)=>s+A[i][k]*row[j],0),q)));
  const U=multiply(W);
  assert(JSON.stringify(U)===JSON.stringify(multiply(Wp)),"different valid witnesses");
  let ell=0,max=1;while(max<2**bits){ell++;max*=base}
  function encrypt(U,a){
    let s=Array.from({length:n},()=>rand()%q),e=Array.from({length:m},()=>rand()%3-1),eps=Array.from({length:d},()=>rand()%3-1);
    const c=Array.from({length:m},(_,k)=>mod(e[k]+s.reduce((sum,z,i)=>sum+A[i][k]*z,0),q));
    const v=Array.from({length:d},(_,j)=>mod(eps[j]+g*a[j]+s.reduce((sum,z,i)=>sum+U[i][j]*z,0),q));
    return {c,v,s,e,eps}
  }
  const digits=x=>{const r=[];for(let i=0;i<ell;i++){r.push(x%base);x=Math.floor(x/base)}return r};
  function encode(U,x){
    let arr=digits(x),out=[];
    for(let i=0;i<ell;i+=d){
      let a=arr.slice(i,i+d);while(a.length<d)a.push(0);
      out.push({a,ct:encrypt(U,a)})
    }
    return out
  }
  function replay(U,share){
    for(const {a,ct} of share){
      for(let k=0;k<m;k++)assert(ct.c[k]===mod(ct.e[k]+ct.s.reduce((v,z,i)=>v+A[i][k]*z,0),q),"sibling c replay");
      for(let j=0;j<d;j++)assert(ct.v[j]===mod(ct.eps[j]+g*a[j]+ct.s.reduce((v,z,i)=>v+U[i][j]*z,0),q),"sibling v replay")
    }
  }
  function decode(share,W){
    const out=[];
    for(const {ct} of share)for(let j=0;j<d;j++){
      let v=mod(ct.v[j]-W.reduce((sum,row,k)=>sum+row[j]*ct.c[k],0),q);
      let dist=a=>Math.min(mod(v-g*a,q),mod(g*a-v,q));
      let best=0;for(let a=1;a<base;a++)if(dist(a)<dist(best))best=a;
      assert(dist(best)<=h+1,"noise margin");out.push(best)
    }
    return out.slice(0,ell).reduceRight((x,a)=>x*base+a,0)
  }
  let siblingN=0;
  for(let run=0;run<12;run++){
    let K=rand()%(2**bits),pad=rand()%(2**bits),Z=Array.from({length:t},()=>rand()%(2**bits));
    let Dmask=Z.reduce((a,b)=>a^b,pad),Vmask=K^pad;
    let ciphers=Z.map(z=>encode(U,z));
    for(let i=0;i<t;i++){
      replay(U,ciphers[i]);
      assert(decode(ciphers[i],W)===Z[i],"opening W");
      assert(decode(ciphers[i],Wp)===Z[i],"opening Wprime")
    }
    for(const open of [W,Wp]){
      let got=Vmask^Dmask;for(const ct of ciphers)got^=decode(ct,open);
      assert(got===K,"same final K")
    }
    let choices=[U,U.map(row=>row.map(()=>0)),U.map(row=>row.map(z=>(2*z)%q)),
      U.map(row=>row.map(z=>mod(z+(Dmask%q),q)))];
    choices.forEach((Ui,j)=>{
      let siblingKey=j%2===0?rand()%(2**bits):(Dmask^(j+101))%(2**bits);
      if(siblingKey===K)siblingKey=(siblingKey+1)%(2**bits);
      let chunks=encode(Ui,siblingKey);
      replay(Ui,chunks);
      assert(siblingKey!==K,"native key distinct");
      siblingN++
    })
  }
  const key=(a,b,u)=>`${a},${b},${u}`;
  let p=new Map(),z=new Map();
  for(let a=0;a<3;a++)for(let b=0;b<3;b++){
    for(const v of [a,mod(-a,3),b,mod(-b,3)]){let k=key(a,b,v);p.set(k,(p.get(k)||0)+1)}
    for(let v=0;v<3;v++)z.set(key(a,b,v),1)
  }
  const extend=(baseMap,M)=>{
    let state=new Map([...baseMap].map(([key,num])=>[key+"|",num]));
    for(let j=0;j<M;j++){
      const next=new Map();
      for(const [str,count] of state){
        let [a,b,u]=str.split("|")[0].split(",").map(Number);
        let prior=str.endsWith("|")?0:Number(str.slice(-2,-1));
        assert(Number.isInteger(prior)&&prior>=0&&prior<=1,"adaptive previous coin");
        let uj=(u+j+prior)%3;
        assert(Number.isInteger(uj)&&uj>=0&&uj<3,"adaptive source field");
        for(let coin=0;coin<2;coin++)for(let secret=0;secret<2;secret++){
          let c=(a*coin+secret)%3,v=(uj*coin+secret)%3;
          let out=str+`${uj}${c}${v}${secret}${coin};`;
          next.set(out,(next.get(out)||0)+count)
        }
      }
      state=next
    }
    return state
  };
  for(let M=0;M<=4;M++){
    let l=extend(p,M),r=extend(z,M),sum=0;
    for(let [k,num] of l)sum+=Math.abs(3*num-4*(r.get(k)||0));
    for(let [k,num] of r)if(!l.has(k))sum+=Math.abs(4*num);
    assert(sum*27===16*108*(4**M),`exact TV adaptive M=${M}`);
    assert([...l.values()].reduce((a,b)=>a+b,0)===36*(4**M),"planted mass");
    assert([...r.values()].reduce((a,b)=>a+b,0)===27*(4**M),"uniform mass")
  }
  return `PASS ${checks} assertions; 12 targets with two distinct accepted openings; ${siblingN} adversarial-source full-coin related capsules; exact TV 8/27 unchanged for 0..4 adaptive related capsules; toy only`
};
console.log(runChecks());
