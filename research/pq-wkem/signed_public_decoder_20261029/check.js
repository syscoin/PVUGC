console.log(JSON.stringify((function verified(){
 let assertions=0,seed=20261029;
 const ok=(v,m)=>{assertions++;if(!v)throw Error(m)};
 const rand=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};
 const mod=(v,q)=>((v%q)+q)%q;
 const product=k=>{let out=[[]];for(let i=0;i<k;i++)out=out.flatMap(a=>[a.concat(0),a.concat(1)]);return out};
 const allowed=f=>product(3).filter(b=>b.some((x,i)=>x!==f.forbid[i]));
 const clauses=[];
 for(const yz of product(2))clauses.push({vs:[0,1,2],forbid:[0,...yz]});
 for(const ab of product(2))clauses.push({vs:[0,3,4],forbid:[1,...ab]});
 const expectation=(cs,a)=>{
   let x=0;
   for(const f of cs){let rem=0,bad=true;
     for(let i=0;i<3;i++){const v=f.vs[i];if(a[v]===undefined)rem++;
       else if(a[v]!==f.forbid[i]){bad=false;break}}
     if(bad)x+=Math.pow(2,-rem);
   }return x;
 };
 const choose=cs=>{
   const vs=[...new Set(cs.flatMap(f=>f.vs))].sort((a,b)=>a-b),a={};
   for(const v of vs){a[v]=0;const left=expectation(cs,a);
     a[v]=1;const right=expectation(cs,a);a[v]=(left<=right?0:1)}
   return a;
 };
 const violated=(cs,a)=>cs.filter(f=>f.vs.every((v,i)=>a[v]===f.forbid[i])).length;
 const flip=(arr,positions)=>arr.map((v,i)=>positions.includes(i)?1-v:v);
 const signed=(cs,a,degree)=>cs.map(f=>{
   const b=f.vs.map(v=>a[v]),m=new Map();
   if(b.some((v,i)=>v!==f.forbid[i]))m.set(b.join(""),1);
   else if(degree===1){m.set(flip(b,[0]).join(""),1);m.set(flip(b,[1]).join(""),1);m.set(flip(b,[0,1]).join(""),-1);}
   else for(let mask=1;mask<8;mask++){
     const inds=[0,1,2].filter(i=>(mask>>i)&1);
     m.set(flip(b,inds).join(""),inds.length%2?1:-1);
   }
   const choices=new Set(allowed(f).map(x=>x.join("")));
   ok([...m.keys()].every(k=>choices.has(k)),"only valid local columns");
   ok([...m.values()].reduce((p,q)=>p+q,0)===1,"normalization");
   return m;
 });
 const compile=(cs,degree)=>{
   const cols=cs.flatMap((f,j)=>allowed(f).map(choice=>({j,choice})));
   const A=[],U=[];
   for(let j=0;j<cs.length;j++){A.push(cols.map(col=>Number(col.j===j)));U.push(1)}
   const scopes=new Map();
   for(let j=0;j<cs.length;j++){const vs=cs[j].vs;
     for(let i=0;i<3;i++){const key=String(vs[i]);if(!scopes.has(key))scopes.set(key,[]);scopes.get(key).push({j,subset:[vs[i]]})}
     if(degree>=2)for(let u=0;u<3;u++)for(let v=u+1;v<3;v++){
       const subset=[vs[u],vs[v]].sort((a,b)=>a-b),key=subset.join(",");
       if(!scopes.has(key))scopes.set(key,[]);
       scopes.get(key).push({j,subset});
     }
   }
   for(const loc of scopes.values())for(let t=1;t<loc.length;t++){
     const root=loc[0],child=loc[t];
     A.push(cols.map(col=>{
       if(col.j!==root.j&&col.j!==child.j)return 0;
       const f=cs[col.j],degreeValue=root.subset.reduce((v,x)=>v*col.choice[f.vs.indexOf(x)],1);
       return col.j===root.j?degreeValue:-degreeValue;
     }));U.push(0);
   }
   return {A,U,cols};
 };
 const makePsi=(cs,source,maps)=>source.cols.map(col=>maps[col.j].get(col.choice.join(""))||0);
 const falseW=product(5);
 ok(falseW.every(bits=>clauses.some(f=>f.vs.every((v,i)=>bits[v]===f.forbid[i]))),"all 32 assignments false");
 const base=choose(clauses),V=violated(clauses,base);
 ok(V===1,"one violated clause");
 const stages={};
 for(const degree of [1,2]){
   const S=compile(clauses,degree),maps=signed(clauses,base,degree),psi=makePsi(clauses,S,maps);
   const norm=psi.reduce((a,b)=>a+Math.abs(b),0);
   ok(norm===(degree===1?10:14),"signed norm");
   for(let i=0;i<S.A.length;i++)ok(S.A[i].reduce((v,x,j)=>v+x*psi[j],0)===S.U[i],"integer public pseudo-opening");
   const q=64,g=32;ok(norm+1<q/4,"max noise below decoding threshold");
   let recoveredKeys=0;
   for(let t=0;t<2;t++){
     const K=Array.from({length:32},()=>rand(256)),shares=Array.from({length:3},()=>Array.from({length:32},()=>rand(256)));
     const mask=K.map((a,i)=>a^shares[0][i]^shares[1][i]^shares[2][i]),R=[];
     for(const share of shares){
       const recovered=[];
       for(let byte=0;byte<32;byte++){
         let value=0;
         for(let bitpos=0;bitpos<8;bitpos++){
           const bit=(share[byte]>>bitpos)&1;
           const s=S.A.map(()=>rand(q)),e=psi.map(()=>rand(3)-1),eps=rand(3)-1;
           const c=psi.map((_,j)=>mod(S.A.reduce((v,row,i)=>v+row[j]*s[i],e[j]),q));
           const d=mod(S.U.reduce((v,u,i)=>v+u*s[i],eps)+g*bit,q);
           const r=mod(d-c.reduce((v,x,i)=>v+x*psi[i],0),q),err=eps-e.reduce((v,x,i)=>v+x*psi[i],0);
           ok(mod(r-g*bit,q)===mod(err,q),"entire ciphertext algebra");
           ok(Math.abs(err)<=norm+1,"worst-case bound");
           const d0=Math.min(r,q-r),d1=Math.abs(r-g);
           const guess=Number(d1<d0);
           ok(guess===bit,"public bit recovery");
           value|=guess<<bitpos;
         }recovered.push(value);
       }R.push(recovered);
     }
     ok(K.every((v,i)=>v===(mask[i]^R[0][i]^R[1][i]^R[2][i])),"whole native mock key, no witness");
     recoveredKeys++;
   }
   stages[String(degree)]={rows:S.A.length,columns:S.cols.length,signedNorm:norm,maxError:norm+1,q,recoveredKeys};
 }
 const large=[],seen=new Set();
 while(large.length<192){
   const vs=[];while(vs.length<3){const v=rand(30);if(!vs.includes(v))vs.push(v)}
   vs.sort((a,b)=>a-b);const k=vs.join(",");
   if(seen.has(k))continue;seen.add(k);
   large.push({vs,forbid:[rand(2),rand(2),rand(2)]});
 }
 ok(seen.size===192,"no possible 4-clause same-scope XOR fold");
 const largeBase=choose(large),LV=violated(large,largeBase);
 ok(LV<=24,"conditional expectation V <= M/8");
 for(const deg of [1,2]){
   const ms=signed(large,largeBase,deg);
   for(let j=0;j<large.length;j++)for(let mask=0;mask<8;mask++){
     const inds=[0,1,2].filter(i=>(mask>>i)&1);
     if(inds.length>deg)continue;
     const actual=[...ms[j]].reduce((s,[str,w])=>{
       const tuple=str.split("").map(Number);
       return s+w*inds.reduce((v,i)=>v*tuple[i],1);
     },0);
     const expected=inds.reduce((s,i)=>s*largeBase[large[j].vs[i]],1);
     ok(actual===expected,"moment interpolation");
   }
 }
 const largeNorm=192+2*LV;
 ok(largeNorm+1<1024/4,"q=1024 public 192-clause all-coins decoder");
 return {status:"PASS",assertions,falseOriginal:{clauses:8,variables:5,satisfyingAssignments:0,baseViolations:V},
   publicDecoders:stages,large3CNF:{clauses:192,variables:30,distinctScopes:192,baseViolations:LV,
     signedNorm:largeNorm,q:1024,guaranteedAllCoinDecoding:true},
   limitation:"No positive secure witness-KEM advance. Mock native key; QPT/Bitcoin not tested."};
})(), null, 2));
