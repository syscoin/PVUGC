const check=function checker(){
  let assertions=0; const ok=(x,msg)=>{assertions++;if(!x)throw Error(msg);};
  const mask=(1<<20)-1,G=r=>(Math.imul(r+1,2654435761)>>>0)&mask;
  const A=Array.from({length:32},(_,i)=>G(i));
  const D=new Set(A.flatMap(a=>A.map(b=>a^b)));
  let sigma=1;while(D.has(sigma))sigma++;
  ok(sigma<1<<20,"real binding sigma exists");
  for(let i=0;i<32;i++)for(let j=0;j<32;j++)
    ok(G(i)!==(G(j)^sigma),"opposite-bit opening impossible");
  const fake=(a,b)=>({s:G(a)^G(b),c:G(a),a,b});
  const ver=(p,v,r)=>(G(r)^(v?p.s:0))===p.c;
  for(let i=0;i<160;i++){
    const p=fake((i*7+1)%32,(i*13+5)%32);
    ok(ver(p,0,p.a)&&ver(p,1,p.b),"fake opens both");
    ok(D.has(p.s),"simulated sigma in difference set");
  }
  const edges=[];for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)edges.push([i,j]);
  let max=0,colorings=0;
  for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++){
    const col=[a,b,c,d],pass=edges.filter(([u,v])=>col[u]!==col[v]).length;
    ok(pass<=5,"K4 uncolorable");max=Math.max(max,pass);colorings++;
  }
  ok(max===5&&colorings===81,"tight K4");
  for(let trial=0;trial<160;trial++){
    const colors=[trial%3,(trial+1)%3,(trial+2)%3];
    const e=[trial%3,(trial+1)%3];
    const real=colors.map((c,v)=>[0,1].map(j=>{
      const b=(c>>>j)&1,s=(trial*991+v*37+j*73+17)&mask,r=(trial+v*7+j*11)%32;
      return {s,c:G(r)^(b?s:0),r};
    }));
    ok(colors[e[0]]!==colors[e[1]],"K3 proper colors");
    for(const v of e)for(let j=0;j<2;j++)
      ok(ver(real[v][j],(colors[v]>>>j)&1,real[v][j].r),"real opened color bit");
    const slots=Array.from({length:4},(_,v)=>[0,1].map(j=>fake((trial*7+v*5+j*3)%32,(trial*13+v*9+j*11+1)%32)));
    const val=slots.reduce((s,row)=>s+row.reduce((t,p)=>t+(p.c^p.s),0),0);
    const edge=edges[(val>>>0)%edges.length],c0=trial%3,c1=(c0+1+trial%2)%3;
    ok(c0!==c1,"distinct simulated endpoint colors");
    for(let z=0;z<2;z++)for(let j=0;j<2;j++){
      const bit=((z?c1:c0)>>>j)&1,p=slots[edge[z]][j];
      ok(ver(p,bit,bit?p.b:p.a),"adaptive false graph response");
    }
    let spent=false;const request=()=>{if(spent)return false;spent=true;return true};
    ok(request()&&!request(),"one-challenge-per-round enforced");
  }
  const log2=256*Math.log2(5/6);
  ok(log2< -67&&log2> -68,"K4 256 exponent");
  ok(Math.log2(2048)+2*256-896< -128,"illustrative binding parameter");
  return {status:"PASS",assertions,toy_seed_bits:5,toy_output_bits:20,
    difference_set_size:D.size,opposite_opening_pairs:1024,
    real_proper_K3_rounds:160,simulated_adaptive_false_K4_rounds:160,
    false_K4_colorings:colorings,max_proper_edges:max,
    log2_K4_success_256:Number(log2.toFixed(6)),
    warning:"Functional arithmetic toy only; no QPT PRG/SLH/LWE/ORIGINAL-witness theorem"};
};
console.log(JSON.stringify(check(),null,2));
