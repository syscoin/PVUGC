function runR165() {
  let rng=165, checks=0, same=0, conflicting=0, falseEarly=0, forgedRejected=0;
  const rand=()=>{rng=(Math.imul(rng,1664525)+1013904223)>>>0;return rng>>>0;};
  const insist=(x,why)=>{checks++;if(!x)throw Error("R165 check "+checks+": "+why);};
  const mix=(s,i,j,b)=>{let x=(s^(Math.imul(i+1,0x9e3779b1))^(Math.imul(j+1,0x85ebca6b))^b)>>>0;x=Math.imul(x^(x>>>16),0x7feb352d);x=Math.imul(x^(x>>>15),0x846ca68b);return (x^(x>>>16))>>>0;};
  for(let trial=0;trial<64;trial++){
    const N=3,L=64,kShare=Array.from({length:N},rand),K=kShare.reduce((a,b)=>a^b,0);
    const pair=Array.from({length:N},(_,j)=>Array.from({length:L},()=>{const a=rand();return [a,a^kShare[j]];}));
    const committed=pair.map((blocks,j)=>blocks.map(([a,b],i)=>[mix(a,i,j,0),mix(b,i,j,1)]));
    const bits=(msg,i)=>{let x=(msg^(Math.imul(i+3,0x9e3779b1)))>>>0;x=Math.imul(x^(x>>>13),0x85ebca6b);return (x>>>((i+trial)%24))&1;};
    const disclose=(msg)=>pair.map(blocks=>blocks.map((vals,i)=>vals[bits(msg,i)]));
    const verify=(msg,sig)=>sig.every((row,j)=>row.every((v,i)=>mix(v,i,j,bits(msg,i))===committed[j][i][bits(msg,i)]));
    const recover=(m0,s0,m1,s1)=>{
      if(!verify(m0,s0)||!verify(m1,s1))return null;
      let result=null;
      for(let i=0;i<L;i++)if(bits(m0,i)!==bits(m1,i)){
        let got=0;for(let j=0;j<N;j++)got^=s0[j][i]^s1[j][i];
        if(result!==null&&result!==got)return null;
        result=got;
      }
      return result;
    };
    const m0=0x10100000^trial, m1=0x70605040^trial, mfake=0xdead0000^trial;
    const a=disclose(m0), b=disclose(m1), f=disclose(mfake);
    insist(verify(m0,a)&&verify(m1,b),"honest signatures");
    insist(recover(m0,a,m0,a)===null,"same semantic outcome cannot release");same++;
    insist(recover(m0,a,m1,b)===K,"all differing positions same setup key");conflicting++;
    insist(verify(mfake,f)&&recover(m0,a,mfake,f)===K,"unauthenticated fake with signer state unlocks");falseEarly++;
    const clone=a.map(row=>row.slice());clone[0][0]^=1;
    insist(!verify(m0,clone),"arbitrary altered revealed label is rejected");forgedRejected++;
  }
  return {run:"R165_v8_hash_label_algebra",checks,sameSemanticOutcomeNoRelease:same,
  differentSignedOutcomeCommonKey:conflicting,invalidSourceSignerRetainsEarlyRelease:falseEarly,
  tamperedLabelRejected:forgedRejected,scope:"finite toy 32-bit label algebra, NOT SHA/PQ/consensus security"};
}
console.log(JSON.stringify(runR165(),null,2));
