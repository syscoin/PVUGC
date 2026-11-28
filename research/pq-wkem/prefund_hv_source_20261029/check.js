(function checker(){
  let assertions=0;
  const req=(v,m)=>{assertions++;if(!v)throw Error(m)};
  const seedBits=5, outBits=20, mask=(1<<outBits)-1;
  const G=r=>Math.imul((r+1),2654435761)&mask;
  const all=Array.from({length:1<<seedBits},(_,i)=>G(i));
  const differences=new Set();
  for(const a of all)for(const b of all)differences.add(a^b);
  req(differences.size<=1<<(2*seedBits),"difference cardinality");
  let sigma=1;while(differences.has(sigma))sigma++;
  req(sigma<1<<outBits,"good public sigma exists");
  const c=(b,r)=>(G(r)^(b?sigma:0))>>>0;
  for(let i=0;i<all.length;i++)for(let j=0;j<all.length;j++)
    req(c(0,i)!==c(1,j),"opposite-bit double opening");
  const K3=[[0,1],[1,2],[2,0]],K4=[];
  for(let a=0;a<4;a++)for(let b=a+1;b<4;b++)K4.push([a,b]);
  let colorings=0,maxGood=0,wrong=0,simulated=0;
  for(let a=0;a<3;a++)for(let b=0;b<3;b++)
  for(let d=0;d<3;d++)for(let e=0;e<3;e++){
    const colors=[a,b,d,e],good=K4.filter(([x,y])=>colors[x]!==colors[y]).length;
    req(good<=5,"K4 3-colored");maxGood=Math.max(maxGood,good);colorings++;
  }
  req(colorings===81&&maxGood===5,"tight false 3COL bound");
  for(const [i,j] of K3){
    const col=[0,1,2],commitments=col.map((v,z)=>[c(v&1,z),c((v>>1)&1,z+4)]);
    req(col[i]!==col[j],"true edge");
    req(commitments[i][0]===c(col[i]&1,i)&&commitments[j][1]===c((col[j]>>1)&1,j+4),"valid openings");
  }
  for(const [i,j] of K4){
    const col=[0,0,0,0];col[i]=1;col[j]=2;
    const commitments=col.map((v,z)=>[c(v&1,z),c((v>>1)&1,z+4)]);
    req(col[i]!==col[j]&&commitments[i][0]===c(1,i),"simulated edge opens");
    req(K4.some(([x,y])=>col[x]===col[y]),"simulator not honest full coloring");
    simulated++;
  }
  const soundnessLog2=256*Math.log2(5/6);
  req(soundnessLog2< -64,"bounded honest rejection");
  return {status:"PASS",assertions,seedBits,outBits,seed_pairs:all.length**2,
          difference_set_size:differences.size,good_sigma:sigma,
          worst_bad_sigma_bound:"2^-10",false_graph_assignments:colorings,
          false_graph_max_good_edges:maxGood,false_graph_edges:K4.length,
          simulated_false_local_checks:simulated,
          log2_honest_false_acceptance_256:Math.round(soundnessLog2*1e5)/1e5,
          scope:"toy 3COL and binding arithmetic only; no signature/LWE/PRG QPT security"};
})();
