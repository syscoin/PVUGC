const executeCheck = function executeCheck(){
  const B=3,cases=[7,9,15,31,63,127];let checks=0;
  const ok=(x,msg)=>{if(!x)throw Error(msg);checks++};
  const isPrime=n=>{if(n<2)return false;for(let d=2;d*d<=n;d++)if(n%d===0)return false;return true};
  const nextPrime=n=>{while(!isPrime(n))n++;return n};
  const gcd=(a,b)=>{while(b!==0n){let t=a%b;a=b;b=t}return a};
  const reduced=(a,b)=>{let g=gcd(a,b);return[a/g,b/g]};
  const hist=coeff=>{let out=new Map([[0,1n]]),den=1n;for(let a of coeff){if(a===0)continue;let next=new Map();for(let[z,k]of out)for(let e=-B;e<=B;e++){let t=z+a*e;next.set(t,(next.get(t)||0n)+k)}out=next;den*=BigInt(2*B+1)}let total=0n;for(let k of out.values())total+=k;ok(total===den,"hist normalization");return{out,den}};
  const dec=(z,q)=>{let g=(q-1)/2;z=((z%q)+q)%q;let d0=Math.min(z,q-z),d1=Math.min(((z-g)%q+q)%q,((g-z)%q+q)%q);return +(d1<d0)};
  let rows=[];
  for(let M of cases){
    const N=M-1,vals=[0,1,1,-1,0,1,...Array(N-6).fill(1)],v=[1],ix=u=>1+2*u;
    for(let value of vals)v.push(value,1-value);
    const equations=[];
    for(let u=0;u<N;u++)equations.push([[ix(u),1],[ix(u)+1,1],[0,-1]]);
    equations.push([[ix(0),1],[ix(1),1],[0,-1]]);
    equations.push([[ix(0),1],[ix(2),-1],[ix(3),-1]]);
    equations.push([[ix(1),1],[ix(2),-1],[ix(4),-1]]);
    equations.push([[0,1],[ix(2),1],[ix(0),-1],[ix(1),-1],[ix(5),-1]]);
    equations.push([[ix(2),1],[0,-1]]);
    ok(equations.every(eq=>eq.reduce((s,[j,a])=>s+a*v[j],0)===0),"public integer kernel");
    ok(v.reduce((s,x)=>s+Math.abs(x),0)===M+2,"L1 gap");
    ok(v.reduce((s,x)=>s+x*x,0)===M+4,"L2 gap");
    let q=nextPrime(4*B*M+3);ok(q>4*B*M+2&&isPrime(q),"completeness modulus");
    let h=hist(Array(M).fill(1)),f=hist(v),s=hist(Array(M-1).fill(1)),fail={};
    for(let b=0;b<=1;b++){
      let a=0n,c=0n,g=(q-1)/2;
      for(let[e,k]of h.out)if(dec(g*b+e,q)!==b)a+=k;
      for(let[e,k]of f.out)if(dec(g*b+e,q)!==b)c+=k;
      ok(a===0n,"honest bounded-error completeness");
      fail["bit"+b]=reduced(c,f.den).map(String);
      let upper=2*Math.exp(-M*M/(2*(M+4)));
      ok(Number(c)/Number(f.den)<=upper+1e-15,"Hoeffding bound");
    }
    let diff=0n;
    for(let z of new Set([...h.out.keys(),...f.out.keys()])){let a=(h.out.get(z)||0n)*f.den,b=(f.out.get(z)||0n)*h.den;diff+=a>b?a-b:b-a}
    let tvN=diff,tvD=2n*h.den*f.den,[tvNum,tvDen]=reduced(tvN,tvD),peak=0n;
    for(let k of s.out.values())if(k>peak)peak=k;
    let ENum=BigInt(4*B*(B+1)),EDen=BigInt(3*(2*B+1));
    ok(tvN*EDen*s.den<=ENum*peak*tvD,"shift-coupling bound");
    for(let b=0;b<=1;b++){let[n,d]=fail["bit"+b].map(BigInt);ok(n*tvDen<=tvNum*d,"decoder contractivity")}
    if(M===7){ok(fail.bit0[0]==="734"&&fail.bit0[1]==="5764801","M7 exact zero bit");ok(fail.bit1[0]==="1287"&&fail.bit1[1]==="5764801","M7 exact one bit")}
    rows.push({M,q,falseNorm:M+2,falseL2Squared:M+4,falseFailureBit0:fail.bit0,falseFailureBit1:fail.bit1,TVExact:[tvNum.toString(),tvDen.toString()],TVApprox:Number(tvNum)/Number(tvDen),TVCouplingUpper:Number(ENum)/Number(EDen)*Number(peak)/Number(s.den)});
  }
  return{run:"BLSC-NOISE-2026-11-01-T14",status:"NO POSITIVE WKEM ADVANCE; parameter repair fails",B,model:"independent uniform bounded integer errors; public source-derived A; no SOURCE-opening oracle",checks,rows};
};
console.log(JSON.stringify(executeCheck(),null,2));
