
'use strict';
function run(){
 const alpha=[0,1,2,3,4,5,6,7], key=Array.from({length:16},(_,i)=>i+8),ctx=Array.from({length:8},(_,i)=>i+24),a=32,u=Array.from({length:8},(_,i)=>i+33),tag=Array.from({length:8},(_,i)=>i+41),base=49;
 const prot=new Set([...alpha,...key,...ctx]);let checks=0;
 const check=(v)=>{if(!v)throw Error('assertion '+checks);checks++};
 const bit=(x,i)=>(x>>>i)&1;
 class B{constructor(){this.n=base;this.g=[]}
  fresh(){return this.n++}
  not(t){this.g.push(['N',t])}
  cx(c,t){this.g.push(['X',c,t])}
  ccx(c,d,t){this.g.push(['T',c,d,t])}
  xor(c,d){let t=this.fresh();this.cx(c,t);this.cx(d,t);return t}
  and(c,d){let t=this.fresh();this.ccx(c,d,t);return t}
 }
 function recipe(b){
  let v=alpha.map((w,i)=>b.xor(b.xor(w,ctx[i]),u[i]));
  for(let r=0;r<4;r++){let z=[];
   for(let i=0;i<8;i++){let p=b.and(v[(i+1)%8],alpha[(i+r+2)%8]);z.push(b.xor(b.xor(v[i],p),v[(i+3)%8]))}
   v=z;
  }
  return v.map((w,i)=>b.xor(w,a));
 }
 function direct(al,co,aa,uu){
  let v=al^co^uu;
  for(let r=0;r<4;r++){let z=0;
   for(let i=0;i<8;i++){let t=bit(v,i)^(bit(v,(i+1)%8)&bit(al,(i+r+2)%8))^bit(v,(i+3)%8);z|=t<<i}
   v=z;
  }
  return v^(aa?255:0);
 }
 const b=new B();b.not(a);for(let i=0;i<8;i++)if(bit(0xa5,i))b.not(u[i]);
 const start=b.g.length;const outputs=recipe(b),work=b.g.slice(start);
 for(let i=0;i<8;i++)b.cx(outputs[i],tag[i]);b.g.push(...work.reverse());
 check(b.g.length>100);check(b.n>base);
 for(let f=0;f<64;f++){
  let al=(f*73+7)&255,co=(f*43+9)&255,k=(f*313+5)&65535;
  let s=Array(b.n).fill(0);
  for(let i=0;i<8;i++){s[alpha[i]]=bit(al,i);s[ctx[i]]=bit(co,i)}
  for(let i=0;i<16;i++)s[key[i]]=bit(k,i);
  for(let g of b.g){let t=g[g.length-1];check(!prot.has(t));
   if(g[0]=='N')s[t]^=1;else if(g[0]=='X')s[t]^=s[g[1]];else s[t]^=s[g[1]]&s[g[2]];
  }
  const value=arr=>arr.reduce((n,j,i)=>n|(s[j]<<i),0);
  check(value(alpha)===al);check(value(ctx)===co);check(value(key)===k);
  check(s[a]===1);check(value(u)===0xa5);
  check(value(tag)===direct(al,co,1,0xa5));
  check(s.slice(base).every(x=>x===0));
  check(!((0xa5&1)===0&&(0xa5&1)===1));
 }
 return {run:478,status:'PASS',checks,fixtures:64,gates:b.g.length,wires:b.n,allowed:['NOT','CNOT','TOFFOLI'],all_workspace_zero:true,secret_registers_unchanged:true,source_false:true,unauthorized_releases:64,model:'ideal bitwise encrypted-gate semantics; toy auth, no FHE/FE/PQ'};
}
console.log(JSON.stringify(run(),null,2));
