'use strict';
// Offline exact finite check: original Macaulay rank-pad FALSE-key recovery.
const triples=[[0,1,2],[0,3,4],[1,3,5],[2,4,5]],parity=[0,0,0,1];
const mons=Array.from({length:64},(_,i)=>i).filter(x=>x.toString(2).replace(/0/g,'').length<=3);
const idx=new Map(mons.map((x,i)=>[x,i]));
const A=[];
for(let j=0;j<4;j++)for(let b=0;b<8;b++){
  const bits=[b&1,(b>>1)&1,(b>>2)&1];
  if(bits.reduce((a,c)=>a+c,0)%2===parity[j])continue;
  let terms=new Map([[0,1]]);
  for(let k=0;k<3;k++){
    let next=new Map(),flag=1<<triples[j][k];
    for(const [mask,v] of terms){
      if(bits[k])next.set(mask|flag,(next.get(mask|flag)||0)+v);
      else {next.set(mask,(next.get(mask)||0)+v);next.set(mask|flag,(next.get(mask|flag)||0)-v);}
    }
    terms=next;
  }
  const row=Array(mons.length).fill(0);
  for(const [mask,v] of terms)row[idx.get(mask)]=v;
  A.push(row);
}
A.push(mons.map(x=>Number(x===0)));
const assert=(b,msg)=>{if(!b)throw Error(msg);checks++};
let checks=0;
assert(A.length===17&&mons.length===42,'matrix size');
for(let a=0;a<64;a++){
  let sat=true;
  for(let j=0;j<4;j++)if(triples[j].reduce((sum,i)=>sum+((a>>i)&1),0)%2!==parity[j])sat=false;
  assert(!sat,'FALSE original relation');
}
let rnd=0x1badb002;
function rand(n){rnd^=rnd<<13;rnd^=rnd>>>17;rnd^=rnd<<5;return (rnd>>>0)%n;}
const mod=(x,q)=>((x%q)+q)%q;
const bytes=()=>Array.from({length:32},()=>rand(256));
function run(q){
  const g=87,p=(q-1)/2,T=Math.floor(q/g),w=Array(42).fill(0);
  for(const [mask,c] of [[0,1],[3,p],[4,1],[5,-p],[6,-p]])w[idx.get(mask)]=c;
  for(let i=0;i<A.length;i++)assert(mod(A[i].reduce((sum,v,j)=>sum+v*w[j],0),q)===Number(i===A.length-1),'public Aw=U');
  const active=w.filter(x=>x!==0),support=new Set();
  for(let ep=-1;ep<=1;ep++)for(let k=0;k<243;k++){
    let n=k,sum=ep;
    for(const c of active){sum-=c*(n%3-1);n=Math.floor(n/3);}
    support.add(mod(sum,q));
  }
  assert(support.size===19,'full support');
  const decoder=new Map();
  for(let a=0;a<T;a++)for(const e of support){
    const r=mod(g*a+e,q);
    assert(!decoder.has(r)||decoder.get(r)===a,'all radix supports disjoint');
    decoder.set(r,a);
  }
  let count=0;
  for(let trial=0;trial<2;trial++){
    const K=bytes(),Z=[bytes(),bytes(),bytes()],mask=K.map((b,j)=>b^Z[0][j]^Z[1][j]^Z[2][j]);
    const recovered=[];
    for(const share of Z){
      let number=share.reduceRight((a,b)=>(a<<8n)+BigInt(b),0n),place=1n,result=0n;
      while(number>0n||place<(1n<<256n)){
        const a=Number(number%BigInt(T));number/=BigInt(T);
        const s=Array.from({length:17},()=>rand(q)),e=Array.from({length:42},()=>rand(3)-1),ep=rand(3)-1;
        const c=mons.map((_,j)=>mod(A.reduce((v,row,i)=>v+row[j]*s[i],e[j]),q));
        const d=mod(s[16]+ep+g*a,q);
        const r=mod(d-w.reduce((v,x,j)=>v+x*c[j],0),q);
        assert(decoder.get(r)===a,'exact public digit recovery under original noise');
        result+=BigInt(decoder.get(r))*place;place*=BigInt(T);count++;
      }
      const out=Array.from({length:32},(_,j)=>Number((result>>BigInt(8*j))&255n));
      recovered.push(out);
    }
    for(let j=0;j<32;j++)assert((mask[j]^recovered[0][j]^recovered[1][j]^recovered[2][j])===K[j],'whole key recovered');
  }
  return {q,radix:T,public_w_support:active.length,error_support:support.size,recovered_ciphertext_digits:count,recovered_full_256bit_capabilities:2};
}
console.log(JSON.stringify({status:'PASS',cases:[run(257),run(65537)],checks,meaning:'deterministic fixed-FALSE full-key recovery; NOT a secure witness-KEM advance'}));
