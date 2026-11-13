const R150Checker = function R150Checker() {
 const q=101;let checks=0;const ck=(v,m)=>{checks++;if(!v)throw Error(m)};
 const add=(...ps)=>{const z={};for(const p of ps)for(const [k,v] of Object.entries(p))z[k]=((z[k]||0)+v+q*3)%q;return Object.fromEntries(Object.entries(z).filter(([k,v])=>v))};
 const sc=(p,c)=>Object.fromEntries(Object.entries(p).map(([k,v])=>[k,((v*c)%q+q)%q]).filter(([k,v])=>v));
 const mul=(p,r)=>{const z={};for(const [ka,a] of Object.entries(p))for(const [kb,b] of Object.entries(r)){const x=ka.split(",").map(Number),y=kb.split(",").map(Number),k=[x[0]+y[0],x[1]+y[1]].join(",");z[k]=((z[k]||0)+a*b)%q;}return Object.fromEntries(Object.entries(z).filter(([k,v])=>v));};
 const ONE={"0,0":1},A={"1,0":1},B={"0,1":1};
 const mons=D=>{const z=[];for(let d=0;d<=D;d++)for(let i=0;i<=d;i++)z.push([i,d-i].join(","));return z};
 const deg=p=>Math.max(0,...Object.keys(p).map(k=>k.split(",").map(Number).reduce((a,b)=>a+b,0)));
 const constraints=y=>[add(A,sc(ONE,-y[0])),add(B,sc(ONE,-y[1])),add(A,B,sc(mul(A,B),-2),sc(ONE,-y[2])),add(mul(A,A),sc(A,-1)),add(mul(B,B),sc(B,-1))];
 const rank=rows=>{const a=rows.map(r=>r.slice()),n=a.length,w=a[0]?.length||0;let t=0;for(let j=0;j<w && t<n;j++){let p=t;while(p<n&&!a[p][j])p++;if(p===n)continue;[a[t],a[p]]=[a[p],a[t]];let inv=1;while(inv*a[t][j]%q!==1)inv++;for(let k=j;k<w;k++)a[t][k]=a[t][k]*inv%q;for(let i=t+1;i<n;i++){const c=a[i][j];for(let k=j;k<w;k++)a[i][k]=((a[i][k]-c*a[t][k])%q+q)%q}t++;}return t};
 const hasRef=(y,D)=>{const base=mons(D),rows=[];for(const g of constraints(y)){for(const m of mons(D-deg(g))){const p=mul(g,{[m]:1});rows.push(base.map(k=>p[k]||0));}}const one=base.map(k=>+(k==="0,0"));return rank(rows.concat([one]))===rank(rows)};
 let trueN=0,falseN=0;
 for(let y0=0;y0<2;y0++)for(let y1=0;y1<2;y1++)for(let y2=0;y2<2;y2++){
  const y=[y0,y1,y2],sat=(y2===(y0^y1));sat?trueN++:falseN++;
  ck(!hasRef(y,1),"degree-1 must be without unit refutation");
  ck(hasRef(y,2)===!sat,"degree-2 certificate exactly false");
  for(let k=0;k<2;k++)for(let r0=0;r0<13;r0++)for(let r1=0;r1<13;r1++){
    const P=add(sc(ONE,k),sc(add(A,sc(ONE,-y0)),r0),sc(add(B,sc(ONE,-y1)),r1));
    let v=0;for(const [mon,c] of Object.entries(P)){const [a,b]=mon.split(",").map(Number);v=(v+c*y0**a*y1**b)%q;}
    ck(v===k,"public degree-1 extraction");
  }
 }
 const g=constraints([0,0,1]);ck(JSON.stringify(add(g[2],sc(g[0],-1),sc(g[1],-1),sc(mul(B,g[0]),2)))===JSON.stringify(sc(ONE,-1)),"degree-2 explicit refutation");
 return {run:"R150-PUBLIC-IDEAL-MASK-20261108",status:"rejected",q,checks,true_outputs:trueN,false_outputs:falseN,public_extractions:8*2*13*13,cryptographic_security_test:false};
};
console.log(JSON.stringify(R150Checker()));
