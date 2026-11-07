function checkR24(){
 const q=65537,Delta=32768;let count=0,seed=2026110224;
 const ok=(x,msg)=>{count++;if(!x)throw new Error("R24 #"+count+" "+msg)};
 const mod=x=>((x%q)+q)%q;
 const rng=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};
 const pop=m=>{let s=0;while(m){s+=m&1;m>>>=1}return s};
 const mons=(n,d)=>Array.from({length:1<<n},(_,i)=>i).filter(m=>pop(m)<=d);
 function source(n,clauses,d){
   const shifts=mons(n,d),cols=[],support=new Set([0]);
   for(const clause of clauses){
     let g=new Map([[0,1]]);
     for(const [i,p] of clause){
       const h=p?new Map([[0,1],[1<<i,-1]]):new Map([[1<<i,1]]);
       const next=new Map();for(const [a,x] of g)for(const [b,y] of h)next.set(a|b,(next.get(a|b)||0)+x*y);
       g=new Map([...next].filter(([_,v])=>v!==0));
     }
     for(const t of shifts){
       const col=new Map();for(const [m,x] of g)col.set(m|t,mod((col.get(m|t)||0)+x));
       for(const [m,x] of [...col])if(!x)col.delete(m);else support.add(m);
       cols.push(col);
     }
   }
   return {shifts,cols,rows:[...support].sort((a,b)=>a-b)};
 }
 const prod=(s,r)=>{const c=new Map(s.rows.map(m=>[m,0]));
   s.cols.forEach((col,i)=>{for(const [m,v] of col)c.set(m,mod(c.get(m)+v*r[i]));});return c};
 const ev=(a,c)=>mod([...c].reduce((sum,[m,v])=>sum+(((a&m)===m)?v:0),0));
 const trueClauses=[[[0,true],[1,false],[2,true]],[[2,false],[4,true],[5,true]],[[1,true],[3,false],[6,false]],[[3,true],[5,false],[7,true]]];
 const T=source(8,trueClauses,1),full=mons(8,4),J=full.filter(m=>!T.rows.includes(m));
 ok(T.rows.length===77&&J.length===86,"correct actual nonzero row set");
 const valid=Array.from({length:256},(_,a)=>a).filter(a=>trueClauses.every(cl=>cl.some(([i,p])=>(!!(a&(1<<i)))===p)));
 ok(valid.length===136,"multiple distinct ORIGINAL witnesses");
 for(let k=0;k<8;k++){
   const bit=k&1,r=T.cols.map(()=>rng()%q),noise=new Map(T.rows.map(m=>[m,rng()%3-1]));
   const c=prod(T,r);for(const m of T.rows)c.set(m,mod(c.get(m)+noise.get(m)+(m===0?Delta*bit:0)));
   const deleted=new Map(J.map(m=>[m,rng()%3-1])),padded=new Map([...c,...deleted]);
   ok(J.every(m=>padded.get(m)===deleted.get(m)),"full-view reconstruction samples only independent noise");
   for(const a of valid){
     for(const col of T.cols)ok(ev(a,col)===0,"ORIGINAL evaluator kills mask");
     const raw=mod(ev(a,c)-Delta*bit),err=raw>q/2?raw-q:raw;
     ok(Math.abs(err)<=T.rows.length,"all witnesses recover same precommitted bit");
   }
   const u=T.cols.map(()=>rng()%q),bu=prod(T,u),derived=new Map(c);
   for(const m of T.rows)derived.set(m,mod(derived.get(m)+bu.get(m)));
   for(const a of valid)ok(ev(a,derived)===ev(a,c),"public derivation preserves raw release");
   for(const m of J)ok(padded.get(m)===deleted.get(m),"derivatives must share one padding sample per base");
 }
 const n=7,clauses=[],signs=[];
 for(let i=0;i<n-1;i++){clauses.push([[i,false],[i+1,true]],[[i,true],[i+1,false]]);signs.push(1,-1)}
 clauses.push([[0,true],[n-1,true]],[[0,false],[n-1,false]]);signs.push(-1,1);
 const F=source(n,clauses,1),t=Array(F.cols.length).fill(0);
 signs.forEach((z,j)=>{t[j*F.shifts.length+F.shifts.indexOf(0)]=mod(-z);t[j*F.shifts.length+F.shifts.indexOf(1)]=mod(2*z)});
 const bt=prod(F,t);
 ok(F.rows.every(m=>bt.get(m)===(m===0?1:0)),"explicit public unit ideal FALSE certificate survives projection");
 for(let a=0;a<(1<<n);a++)ok(!clauses.every(cl=>cl.some(([i,p])=>(!!(a&(1<<i)))===p)),"FALSE instance");
 for(let k=0;k<40;k++){
   const bit=rng()&1,r=F.cols.map(()=>rng()%q),e=new Map(F.rows.map(m=>[m,rng()%3-1]));
   const c=prod(F,r),rp=r.map((z,j)=>mod(z+Delta*bit*t[j])),sim=prod(F,rp);
   for(const m of F.rows)ok(mod(c.get(m)+e.get(m)+(m===0?Delta*bit:0))===mod(sim.get(m)+e.get(m)),
    "exact joint FALSE-mask shift without SOURCE oracle");
 }
 return {run:"MINK-SPARSE-SUPPORT-R24",passed:true,checks:count,true:{rows:T.rows.length,deleted:J.length,validOriginalWitnesses:valid.length},false:{rows:F.rows.length,nonzeroCertificateEntries:t.filter(Boolean).length},security:"Only row-projection equivalence; original arbitrary-FALSE and hard-TRUE vulnerabilities remain"};
}
console.log(JSON.stringify(checkR24(),null,2));
