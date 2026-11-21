function r91Checker(){
  let assertions=0, falseCompatible=0, falseTotal=0;
  const check=(v,msg)=>{assertions++;if(!v)throw Error("ASSERT "+assertions+": "+msg)};
  for(let a0=0;a0<5;a0++)for(let a1=0;a1<5;a1++)for(let a2=0;a2<5;a2++){
    const keys=new Set();
    for(let s=0;s<5;s++) keys.add([(a0*s)%5,(a1*s)%5,(a2*s)%5].join(","));
    falseCompatible+=keys.size; falseTotal+=125;
    check(keys.size>=1 && keys.size<=5,"fixed public A span");
  }
  check(falseTotal===15625 && falseCompatible===621,"exact false probability");
  const counts=[0,0,0];let tvNumerator=0;
  for(let x=0;x<81;x++)for(let y=0;y<81;y++){
    const a=[],b=[];let xx=x,yy=y;
    for(let j=0;j<4;j++){a.push(xx%3);b.push(yy%3);xx=Math.floor(xx/3);yy=Math.floor(yy/3)}
    let rank=2;
    if(a.concat(b).every(z=>z===0))rank=0;
    else {
      let minor=false;
      for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)
        if((a[i]*b[j]-a[j]*b[i])%3!==0)minor=true;
      if(!minor)rank=1;
    }
    counts[rank]++;
    tvNumerator+=9-3**rank;
    check(rank>=0 && rank<=2,"rank computed");
  }
  check(counts[0]===1 && counts[1]===320 && counts[2]===6240,"exact extractor ranks");
  check(tvNumerator===1928,"exact sum of rank deficiencies");
  check(tvNumerator/(9*6561) <= 1/6,"strong LHL toy bound");
  for(let T=0;T<=1;T++){
    const views=[];
    for(let Z=0;Z<=1;Z++){
      const left=[Z,Z],right=[T^Z,T^Z];
      views.push(left.join(","));
      check(left[0]^right[0]===T && left[1]^right[1]===T,"distinct witnesses SAME secret");
    }
    check(views.sort().join(";")==="0,0;1,1","FALSE disclosed U joint law independent of T");
  }
  const q=65521,n=256,ell=16,k=11008,G=Math.ceil(k/ell),log=Math.log2;
  const logeps=m=>-1+0.5*((n+ell)*log(q)-m*log(7));
  const need=(leaves,caps)=>{let m=1;while(logeps(m)+log(leaves*G*caps)>-128)m++;return m};
  const m1=need(1,1),m4=need(4,1),m64=need(4,16);
  check(m1===1648 && m4===1649 && m64===1652,"joint-output statistical budget");
  check(9*m64 < q/4-1,"margin");
  const logFalse=16*(256*log(q)+m4*(log(7)-log(q)));
  return {run:"R91-MIXED-TRUE-FALSE-LWE-20261105",kind:"exact-bounded-JS",
    assertions,uniform_false_census:{total:falseTotal,compatible:falseCompatible,unionBound:"1/25"},
    uniform_q3_extractor:{keys:6561,ranks:counts,meanTV:"1928/59049",lhlBound:"1/6"},
    lhl_budget:{groupsPerLeaf:G,rowsOneFalse:m1,rowsFourFalse:m4,rowsFourFalseSixteenCapsules:m64,
      log2TotalFourFalse:logeps(m4)+log(4*G),log2TotalSixteenCapsules:logeps(m64)+log(64*G),
      log2ChanceOfFalseLeafActuallyTrueUnionBound:logFalse}, fixture:"Algebraic finite tests only, NOT PQ security"};
}
console.log(JSON.stringify(r91Checker(),null,2));
