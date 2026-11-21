const runCheck = function runCheck(){
  const q=5; let assertions=0;const counts={};
  const mod=v=>((v%q)+q)%q;
  const check=(b,k)=>{assertions++;counts[k]=(counts[k]||0)+1;if(!b)throw Error(k+" #"+assertions);};
  const zero=n=>Array(n).fill(0).join(",");
  const unit=(n,i)=>{let e=Array(n).fill(0);e[i]=1;return e.join(",");};
  const con=(n,v)=>mod(v)?{[zero(n)]:mod(v)}:{};
  const vr=(n,i)=>({[unit(n,i)]:1});
  const add=(a,b)=>{let r={...a};for(const [k,v] of Object.entries(b)){r[k]=mod((r[k]||0)+v);if(!r[k])delete r[k];}return r;};
  const scale=(a,t)=>Object.fromEntries(Object.entries(a).map(([k,v])=>[k,mod(v*t)]).filter(z=>z[1]));
  const sub=(a,b)=>add(a,scale(b,-1));
  const mul=(a,b)=>{let r={};for(const [ak,av] of Object.entries(a))for(const [bk,bv] of Object.entries(b)){
      const k=ak.split(",").map((x,i)=>+x+(+bk.split(",")[i])).join(",");
      r[k]=mod((r[k]||0)+av*bv);if(!r[k])delete r[k];}return r;};
  const reduce=a=>{let r={};for(const [k,v] of Object.entries(a)){const t=k.split(",").map(x=>+x?1:0).join(",");
    r[t]=mod((r[t]||0)+v);if(!r[t])delete r[t];}return r;};
  const evalAt=(a,w)=>mod(Object.entries(a).reduce((t,[k,v])=>t+v*k.split(",").reduce((u,e,i)=>u*Math.pow(w[i],+e),1),0));
  const formula=(n,cls)=>{let R=con(n,1);for(const cl of cls){let unsat=con(n,1);for(const [i,pos] of cl){
    let lit=pos?vr(n,i):sub(con(n,1),vr(n,i));unsat=mul(unsat,sub(con(n,1),lit));}
    R=mul(R,sub(con(n,1),unsat));}return R;};
  const masks=(n,D)=>{let result=[];function walk(i,e,left){if(i===n){result.push(e.join(","));return;}
    for(let a=0;a<=left;a++){e.push(a);walk(i+1,e,left-a);e.pop();}}
    walk(0,[],D);return result;};
  const vanish=(n,i)=>sub(mul(vr(n,i),vr(n,i)),vr(n,i));
  const blinded=(n,K,R,Qs)=>Qs.reduce((p,Qi,i)=>add(p,mul(vanish(n,i),Qi)),scale(R,K));
  const eq=(a,b)=>JSON.stringify(Object.entries(a).sort())===JSON.stringify(Object.entries(b).sort());
  const Rfalse=formula(1,[[[0,true]],[[0,false]]]);
  check(eq(reduce(Rfalse),{}),"false-quotient-zero");
  let base=null;
  for(let K=0;K<5;K++){
    const hist={};
    for(let a=0;a<5;a++)for(let b=0;b<5;b++){
      const Q={"0":a,"1":b};
      const F=blinded(1,K,Rfalse,[Q]);
      const v=[0,1,2,3].map(i=>F[""+i]||0).join(",");
      hist[v]=(hist[v]||0)+1;
      check(evalAt(F,[0])===0&&evalAt(F,[1])===0,"false-all-boolean");
    }
    if(base)check(eq(hist,base),"full-false-coefficient-histogram");else base=hist;
  }
  check(Object.keys(base).length===25,"false-uniform-25-image-support");
  const Rtrue=formula(3,[[[0,true],[1,true]],[[0,false],[2,true]]]);
  const RT=reduce(Rtrue);
  check(Object.keys(RT).length>0,"true-quotient-nonzero");
  let seed=11420261106>>>0;
  const rand=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return (seed>>>0)%5;};
  const mon=masks(3,3);
  const all=[...Array(8)].map((_,i)=>[i&1,(i>>1)&1,(i>>2)&1]);
  const good=all.filter(w=>evalAt(Rtrue,w)===1);
  check(good.length===4,"four-distinct-witnesses");
  const [where,coef]=Object.entries(RT).find(z=>z[1]);
  for(let K=0;K<5;K++)for(let t=0;t<40;t++){
    const Qs=[...Array(3)].map(()=>Object.fromEntries(mon.map(k=>[k,rand()]).filter(z=>z[1])));
    const F=blinded(3,K,Rtrue,Qs);
    check(good.every(w=>evalAt(F,w)===K),"all-witnesses-common-K");
    check(all.filter(w=>!good.some(v=>v.join()==w.join())).every(w=>evalAt(F,w)===0),"invalid-boolean-zero");
    const recovered=mod((reduce(F)[where]||0)*([0,1,3,2,4][coef]||1));
    // Explicit modular inverse (prime 5) without any witness.
    const inv=[0,1,3,2,4][coef];
    check(mod((reduce(F)[where]||0)*inv)===K,"public-quotient-recovers-K");
    check(eq(reduce(F),scale(RT,K)),"quotient-normalization");
  }
  const ranks=[];const rank=rows=>{let M=rows.map(r=>r.slice()),h=0;for(let j=0;j<(M[0]?.length||0);j++){
    let k=h;while(k<M.length&&!mod(M[k][j]))k++;if(k===M.length)continue;
    [M[h],M[k]]=[M[k],M[h]];const inv=[0,1,3,2,4][mod(M[h][j])];M[h]=M[h].map(z=>mod(z*inv));
    for(let i=0;i<M.length;i++)if(i!==h&&M[i][j]){let a=M[i][j];M[i]=M[i].map((z,l)=>mod(z-a*M[h][l]));}
    h++;if(h===M.length)break;}return h;};
  for(const [n,D] of [[1,3],[2,3],[3,3],[3,4]]){
    const basis=masks(n,D),qb=masks(n,D-2),sq=[...Array(1<<n)].map((_,i)=>[...Array(n)].map((_,j)=>(i>>j)&1));
    const image=[];
    for(let i=0;i<n;i++)for(const m of qb){const g=mul(vanish(n,i),{[m]:1});image.push(basis.map(k=>g[k]||0));}
    const erank=rank(basis.map(k=>sq.map(w=>evalAt({[k]:1},w))));
    const irank=rank(image);
    check(irank+erank===basis.length,"degree-bounded-ideal-surjection");
    ranks.push({n,D,coefficients:basis.length,ideal_rank:irank,quotient_rank:erank});
  }
  return {run:"R114-GLOBAL-BOOLEAN-QUOTIENT-MASK-20261106",status:"REJECTED / NO SECURE WKEM ADVANCE",assertions,counts,
    false_full_coefficient_distributions_identical:true,true_valid_original_witnesses:good.length,
    true_key_recovered_without_witness:true,mask_dimension_checks:ranks};
};
console.log(JSON.stringify(runCheck(),null,2));
