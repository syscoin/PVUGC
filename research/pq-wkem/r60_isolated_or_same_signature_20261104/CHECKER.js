function run(){
  'use strict';
  let checks=0,seed=0x60a57c;
  const ok=(v,m)=>{checks++;if(!v)throw Error(m)};
  const rnd=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0};
  const r=(n)=>Array.from({length:n},()=>rnd()%16);
  const mod=(x,n)=>((x%n)+n)%n;
  const q=65537,delta=1000,B=3;
  const fsrc=(mu,noise)=>[noise[0],noise[1]]; // P(1)=0 for R_F: z0 AND !z0
  const tsrc=(mu,noise)=>[mod(delta*mu+noise[0]+noise[1],q),mod(-noise[1],q)];
  const topen=(z,w)=>{ok(w===1||w===3,'actual ORIGINAL TRUE witness');
    const v=mod(z[0]+z[1],q),candidates=Array.from({length:16},(_,mu)=>({mu,e:Math.min(mod(v-delta*mu,q),q-mod(v-delta*mu,q))})).sort((a,b)=>a.e-b.e);
    ok(candidates[0].e<=1&&candidates[0].e<candidates[1].e,'TRUE cyclic opening exact');return candidates[0].mu};
  const yof=(A,s,e)=>A.map((row,i)=>mod(row.reduce((a,x,j)=>a+x*s[j],0)+e[i],16));
  const hash=str=>{let h=2166136261;for(let i=0;i<str.length;i++)h=Math.imul(h^str.charCodeAt(i),16777619);return(h>>>0).toString(16)};
  const x=(a,b)=>a.map((v,i)=>v^b[i]);
  const sig=[3,12,9,6],sigR=[2,11,0,15];
  const ctx='claim|UTXO|anchors|window|burn|branch|vk|auth-manifest';
  const manifest='signed N-of-N OR[0,1,2];related claim 3 separate';
  const msg='native-challenge-OR-path',msgR='native-different-related-path';
  const tape=()=>({s:r(2),e:Array.from({length:4},()=>rnd()%3-1),k:r(2),noise:Array.from({length:8},()=>[rnd()%3-1,rnd()%3-1])});
  const source=(T,truth)=>{const words=T.s.concat(T.e.map(v=>v+1),T.k);
    return words.map((mu,i)=>truth?tsrc(mu,T.noise[i]):fsrc(mu,T.noise[i]))};
  const seal=(rec,A)=>{const base=JSON.stringify({ctx,manifest,A,raw:rec.map(v=>({id:v.id,msg:v.msg,D:v.D,Z:v.Z}))});
    return rec.map(v=>{const CK=hash('CK|'+v.k+'|'+v.id+'|'+base);return {...v,CK,Aux:hash('AUX|'+v.k+'|'+v.id+'|'+CK+'|'+base)}})};
  const visible=(rec,A)=>JSON.stringify({ctx,manifest,A,rec:rec.map(({k,...v})=>v)});
  const build=(A,T,k,challenge=null,Y=null,truths=[false,false,false,true])=>{
    const out=[];for(let j=0;j<4;j++){
      const p=challenge===j?Y:yof(A,T[j].s,T[j].e);
      const Z=challenge===j?T[j].noise.map(n=>fsrc(0,n)):source(T[j],truths[j]);
      out.push({id:j,msg:j===3?msgR:msg,D:x(j===3?sigR:sig,p),Z,k:T[j].k});
    }return seal(out,A)
  };
  const open=(v,w)=>{const words=v.Z.map(z=>topen(z,w));return {sig:x(v.D,yof(v.A,words.slice(0,2),words.slice(2,6).map(t=>t-1))),k:words.slice(6)}};
  let couplings=0,relatedOpens=0,mixedOpens=0,uniformChecks=0;
  for(let k=0;k<64;k++){
    const A=Array.from({length:4},()=>r(2)),T=Array.from({length:4},tape),real=build(A,T);
    for(let j=0;j<B;j++){
      const Y=yof(A,T[j].s,T[j].e),scrub=T.map((v,i)=>i===j?{noise:v.noise,k:v.k}:v);
      const sim=build(A,scrub,k,j,Y);ok(visible(real,A)===visible(sim,A),'exact all-correlations joint simulator');couplings++;
      const o=open({...sim[3],A},k%2?1:3);ok(JSON.stringify(o.sig)===JSON.stringify(sigR),'related TRUE opening');relatedOpens++;
    }
    const j=k%B,nonsecret=T.map((v,i)=>i===j?{noise:v.noise,k:v.k}:v);
    const U=r(4),hybrid=build(A,nonsecret,k,j,U);
    ok(JSON.stringify(hybrid[j].D)===JSON.stringify(x(sig,U)),'uniform challenge transcript');uniformChecks++;
  }
  for(let k=0;k<64;k++){
    const A=Array.from({length:4},()=>r(2)),T=Array.from({length:4},tape);
    const rec=build(A,T,k,null,null,[true,true,false,true]);
    for(let j=0;j<2;j++)for(const w of [1,3]){
      const o=open({...rec[j],A},w);ok(JSON.stringify(o.sig)===JSON.stringify(sig),'same original precommitted capability');
      ok(JSON.stringify(o.k)===JSON.stringify(T[j].k),'branch-local CK seed opening');mixedOpens++;
    }
  }
  for(let sigma=0;sigma<4;sigma++){let pairs=new Set();for(let a=0;a<4;a++)for(let b=0;b<4;b++)pairs.add(JSON.stringify([sigma^a,sigma^b]));
    ok(pairs.size===16,'two independent uniform pads jointly hide common signature')}
  return {id:'R60-ISOLATED-OR-SAME-SIGNATURE-20261104',checks,couplings,relatedOpens,mixedOpens,uniformChecks,certifiedFalseSecurity:'conditional',hardTrueSecurity:'unproved',toyOnly:true};
}
console.log(JSON.stringify(run()));
