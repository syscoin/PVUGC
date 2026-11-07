const runBasoChecker = function runBasoChecker() {
  "use strict";
  let assertions=0; const ok=(v,m)=>{if(!v)throw Error(m);assertions++;};
  const q=65537,d=2,n=6,B=2,b=3,L=18,C=3,g=Math.floor(q/(1<<b));
  let state=0xB45A2026>>>0; const rand=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state;};
  const r=(n)=>rand()%n;
  const mod=(v)=>((v%q)+q)%q;
  const dot=(x,y)=>mod(x.reduce((a,v,i)=>a+v*y[i],0));
  const col0=[r(q),r(q)],col2=[r(q),r(q)];
  const cols=[col0,col0.slice(),col2,...Array.from({length:3},()=>[r(q),r(q)])];
  const A=Array.from({length:d},(_,i)=>cols.map(v=>v[i]));
  const w0=[1,0,1,0,0,0],w1=[0,1,1,0,0,0],t=A.map(row=>dot(row,w0));
  ok(w0.some((v,i)=>v!==w1[i]),"different binary witnesses");
  for(const w of [w0,w1])ok(A.every((row,i)=>dot(row,w)===t[i]),"source witness check");
  const K=r(1<<L);
  const shares=Array.from({length:C},()=>{const a=r(1<<L),b=r(1<<L);return [a,b,K^a^b];});
  const encrypt=(m)=>{
    const s=[r(q),r(q)],e=Array.from({length:n},()=>r(2*B+1)-B),es=r(2*B+1)-B;
    return {beta:Array.from({length:n},(_,i)=>mod(dot(cols[i],s)+e[i])),
      tau:mod(dot(t,s)+es+g*m),coins:{s,e,es},m};
  };
  const cts=shares.map(sh=>sh.map(bits=>Array.from({length:Math.ceil(L/b)},(_,j)=>encrypt((bits>>>(b*j))&7))));
  const decode=(ct,w)=>{
    const v=mod(ct.tau-dot(w,ct.beta));
    let best=0,dist=Infinity;
    for(let m=0;m<(1<<b);m++){const delta=mod(v-g*m),di=Math.min(delta,q-delta);if(di<dist){dist=di;best=m;}}
    return best;
  };
  for(let c=0;c<C;c++)for(const w of [w0,w1]){
    let recovered=0;
    for(let lane=0;lane<3;lane++){
      let sh=0;
      for(let j=0;j<Math.ceil(L/b);j++){
        const m=decode(cts[c][lane][j],w);
        ok(m===((shares[c][lane]>>>(b*j))&7),"LWE symbol");
        sh|=m<<(b*j);
      }
      recovered^=sh;
    }
    ok(recovered===K,"same bound capability");
  }
  const subsets=[[],[0],[1],[2],[0,1],[0,2],[1,2]];
  for(const O of subsets){
    for(let Kbit=0;Kbit<2;Kbit++){
      const counts=new Map();
      for(let u0=0;u0<2;u0++)for(let u1=0;u1<2;u1++){
        const v=[u0,u1,Kbit^u0^u1],s=O.map(i=>v[i]).join("");
        counts.set(s,(counts.get(s)||0)+1);
      }
      ok(counts.size===2**O.length,"uniform shares");
      for(const count of counts.values())ok(count===2**(2-O.length),"constant multiplicity");
    }
    const weighted=[0,1,2].filter(j=>!O.includes(j)).reduce((a)=>a+1/(3*(3-O.length)),0);
    ok(Math.abs(weighted-1/3)<1e-13,"inverse survival");
  }
  let accepted=0,rejected=0,coinQueries=0;
  for(let trial=0;trial<150;trial++){
    const disclosed=Array.from({length:C},()=>Array.from({length:L},()=>new Set()));
    for(let z=0;z<30;z++){
      const c=r(C),lane=r(3),k=r(L),coins=(r(5)===0);
      const lo=Math.floor(k/b)*b,positions=coins?Array.from({length:Math.min(b,L-lo)},(_,v)=>lo+v):[k];
      if(positions.some(bit=>disclosed[c][bit].size===2&&!disclosed[c][bit].has(lane))){rejected++;continue;}
      for(const bit of positions){
        disclosed[c][bit].add(lane);
        ok(((shares[c][lane]>>>bit)&1)<2,"real share bit");
      }
      if(coins){
        const ct=cts[c][lane][Math.floor(k/b)],{s,e,es}=ct.coins;
        ok(mod(dot(t,s)+es+g*ct.m)===ct.tau,"opened tau coins");
        for(let i=0;i<n;i++)ok(mod(dot(cols[i],s)+e[i])===ct.beta[i],"opened beta coins");
        coinQueries++;
      }
      accepted++;
    }
    for(let c=0;c<C;c++)for(let k=0;k<L;k++){
      const O=disclosed[c][k];ok(O.size<=2,"no complete bit disclosure");
      let sum=0;for(let j=0;j<3;j++)if(!O.has(j))sum+=1/(3*(3-O.size));
      ok(Math.abs(sum-1/3)<1e-13,"adaptive normalization");
    }
  }
  for(let c=0;c<C;c++)for(let k=0;k<L;k++){
    const bit=[0,1,2].reduce((a,lane)=>a^((shares[c][lane]>>>k)&1),0);
    ok(bit===((K>>>k)&1),"negative: all 3 leak K bit");
  }
  return {candidate:"BASO",toy:{q,d,n,B,b,payload_bits:L,capsules:C,valid_source_witnesses:2},
    assertions,opening_trials:150,accepted,rejected,coinQueries,
    allowed_bit_opening_subsets:subsets.length,cross_capsule_opening_patterns:subsets.length**C,
    LWE_hybrid_factor_toy:6*C*L,LWE_hybrid_factor_raw512_two_capsules:6*2*512,
    security_note:"Deterministic finite arithmetic only; does not test QPT hardness or ORIGINAL relation"};
};
console.log(JSON.stringify(runBasoChecker(),null,2));
