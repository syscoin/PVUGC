function run512Check(){
  const c={exhaustive_S8_frames:0,sampled_S16_frames:0,transplant_algebra:0,full_public_multiset_equalities:0,mask_reuse_leaks:0,reference_masks:0};
  const ensure=(p,m)=>{if(!p)throw Error("CHECK_FAILED:"+m)};
  function check(P,h){
    const n=1,N=1<<(h+n+1),H=1<<h;
    ensure(P.length===N&&new Set(P).size===N,"permutation");
    const inv=Array(N);for(let s=0;s<N;s++)inv[P[s]]=s;
    const flip=Array.from({length:N},(_,y)=>P[inv[y]^2]);
    for(let dr=0;dr<H;dr++){
      const ops=Array.from({length:h},(_,i)=>Array.from({length:N},(_,y)=>{
        const s=inv[y],z=(s>>1)&1,u=s>>(n+1);
        return (z&&(((u^dr)>>i)&1))?P[s^1]:y;
      }));
      let baseline=null;
      for(let K=0;K<H;K++){
        const view=[];
        for(let dx=0;dx<H;dx++){
          const a=P[(K^dx)<<(n+1)],y=flip[a];
          let v=0;for(let i=0;i<h;i++)v|=Number(ops[i][y]!==y)<<i;
          ensure(v===(K^dx^dr),"transplant");c.transplant_algebra++;
          view.push(JSON.stringify([a,y,ops.map(o=>o[y]),v]));
          if(dx===dr){ensure(v===K,"mask reuse");c.mask_reuse_leaks++;}
        }
        view.sort(); const key=JSON.stringify(view);
        if(baseline===null)baseline=key;
        else{ensure(key===baseline,"fresh-mask multiset");c.full_public_multiset_equalities++;}
      }
      c.reference_masks++;
    }
  }
  function next(a){
    let j=a.length-2;while(j>=0&&a[j]>=a[j+1])j--;
    if(j<0)return false;
    let k=a.length-1;while(a[k]<=a[j])k--;
    [a[j],a[k]]=[a[k],a[j]];
    let l=j+1,r=a.length-1;
    while(l<r){[a[l],a[r]]=[a[r],a[l]];l++;r--;}
    return true;
  }
  const p=Array.from({length:8},(_,i)=>i);
  do{check(p,1);c.exhaustive_S8_frames++;}while(next(p));
  let rng=0x51220261|0;
  function random(){rng^=rng<<13;rng^=rng>>>17;rng^=rng<<5;return rng>>>0;}
  for(let j=0;j<128;j++){
    const p=Array.from({length:16},(_,i)=>i);
    for(let i=15;i>0;i--){const k=random()%(i+1);[p[i],p[k]]=[p[k],p[i]];}
    check(p,2);c.sampled_S16_frames++;
  }
  ensure(c.exhaustive_S8_frames===40320&&c.transplant_algebra===330752&&c.full_public_multiset_equalities===82176,"counts");
  return {run:512,scope:"false-target complete public-view coupling under independently secret per-claim seed translations; compact/QPT-white-box security unproved",counts:c,negative_control:"shared target/reference delta leaks full target seed"};
}
process.stdout.write(JSON.stringify(run512Check(),null,2)+"\n");
