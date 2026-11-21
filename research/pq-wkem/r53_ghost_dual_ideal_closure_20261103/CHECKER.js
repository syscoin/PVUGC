const result=(function checker(){
 const Q=65537,D=32768,M=64;
 const cls=[
 [[1,3,4],[0,0,0]],[[0,1,4],[0,0,0]],[[0,1,4],[1,0,1]],[[1,3,5],[1,0,1]],[[1,3,4],[1,0,0]],[[0,1,2],[0,0,0]],[[0,3,4],[0,1,1]],[[2,3,5],[1,0,0]],[[0,4,5],[1,1,0]],[[1,2,5],[1,1,1]],[[0,3,4],[1,0,0]],[[0,4,5],[0,0,1]],[[2,4,5],[1,0,0]],[[2,3,4],[0,1,1]],[[0,3,5],[0,0,1]],[[0,4,5],[0,1,0]],[[1,3,4],[0,1,0]],[[1,2,4],[1,1,0]]
 ];
 let checks=0; const ck=(p,s)=>{checks++;if(!p)throw Error(s)};
 const mod=x=>((x%Q)+Q)%Q;
 const mul=(p,r)=>{let a=Array(M).fill(0);for(let i=0;i<M;i++)if(p[i])for(let j=0;j<M;j++)if(r[j])a[i|j]+=p[i]*r[j];return a};
 const cn=k=>{let a=Array(M).fill(0);a[0]=k;return a};
 const unit=k=>{let a=Array(M).fill(0);a[1<<k]=1;return a};
 const fail=([vars,bits])=>{let p=cn(1);for(let j=0;j<3;j++){let f=bits[j]?unit(vars[j]):cn(1).map((v,i)=>v-unit(vars[j])[i]);p=mul(p,f)}return p};
 const ev=(a,w)=>a.reduce((s,v,i)=>s+((w&i)===i?v:0),0);
 const fs=cls.map(fail),val=Array.from({length:64},(_,i)=>i).filter(w=>fs.every(f=>ev(f,w)===0));
 ck(val.join(",")==="10,11,43","valid original assignments");
 const G=[];for(let i=0;i<fs.length;i++)for(let j=i;j<fs.length;j++)G.push(mul(fs[i],fs[j]));
 const rank=arr=>{let rows=arr.map(row=>row.map(mod)),piv=[],h=0;for(let c=0;c<M&&h<rows.length;c++){let k=rows.findIndex((row,i)=>i>=h&&row[c]);if(k<0)continue;[rows[h],rows[k]]=[rows[k],rows[h]];let scale=1,b=rows[h][c],e=Q-2;while(e){if(e&1)scale=mod(scale*b);b=mod(b*b);e=Math.floor(e/2)}rows[h]=rows[h].map(v=>mod(v*scale));for(let j=0;j<rows.length;j++)if(j!==h){let t=rows[j][c];if(t)rows[j]=rows[j].map((v,i)=>mod(v-t*rows[h][i]))}piv.push(c);h++}return {r:h,rows:rows.slice(0,h),piv}};
 const R=rank(G);ck(R.r===49&&G.length===171,"original R46 rank");
 const free=Array.from({length:M},(_,i)=>i).filter(i=>!R.piv.includes(i));
 const P=a=>{let t=a.map(mod);R.piv.forEach((c,i)=>{let z=t[c];if(z)t=t.map((v,j)=>mod(v-z*R.rows[i][j]))});return free.map(c=>t[c])};
 const S=z=>{let a=Array(M).fill(0);free.forEach((j,i)=>a[j]=z[i]);return a};
 let h=Array(M).fill(0);for(const [j,z] of [[0,1],[2,1],[8,1],[10,1],[32,-1],[33,-1]])h[j]=z;
 ck(h[0]===1&&h.reduce((s,v)=>s+Math.abs(v),0)===6,"short ghost");
 const dot=(a,b)=>a.reduce((s,v,j)=>s+v*b[j],0);
 for(const g of G)ck(dot(h,g)===0,"ghost annihilator");
 const E=val.map(w=>Array.from({length:M},(_,j)=>(w&j)===j?1:0));
 ck(rank(E).r===3&&rank([...E,h]).r===4,"ghost not ORIGINAL evaluation span");
 for(let j=0;j<M;j++){let u=Array(M).fill(0);u[j]=1;ck(mod(dot(h,S(P(u))))===mod(h[j]),"quotient consistency")}
 const noise=i=>Array.from({length:M},(_,j)=>((i*1315423911+j*2654435761)&1)?1:-1);
 const cap=(bit,i)=>P(Array.from({length:M},(_,j)=>(j===0?D*bit:0)+noise(i)[j]));
 const dec=t=>{let x=mod(t),d0=Math.min(x,Q-x),d1=Math.min(mod(x-D),mod(D-x));return +(d1<d0)};
 const attack=z=>dec(dot(h,S(z)));
 const actual=(z,w)=>dec(ev(S(z),w));
 const bits=(v,n)=>Array.from({length:n},(_,i)=>(v>>(n-i-1))&1),num=z=>z.reduce((s,b)=>2*s+b,0);
 const root=bits(0x96,8),ss=[2,4,7,12],ee=[-1,0,0,-1],bind=[1,0,1,0],seed=[...root,...ss.flatMap(v=>bits(v,4)),...ee.flatMap(v=>bits(v+1,2)),...bind];
 const C=seed.map((v,i)=>cap(v,37*i+11)),recovered=C.map(attack);
 ck(JSON.stringify(recovered)===JSON.stringify(seed),"full precommitted source seed bypass");
 for(const w of val)ck(C.every((z,i)=>actual(z,w)===seed[i]),"every witness opens same source");
 const a0=[3,5,7,11],expand=r=>{let sk=num(r.slice(0,4)),error=r.slice(4).map(v=>v-1);return a0.flatMap((a,i)=>bits(((a*sk+error[i])%16+16)%16,4))};
 const matrix=r=>{let lv=[r];for(let t=0;t<3;t++)lv=lv.flatMap(v=>{let x=expand(v);return [x.slice(0,8),x.slice(8)]});let b=lv.flat();return Array.from({length:4},(_,i)=>Array.from({length:4},(_,j)=>num(b.slice(16*i+4*j,16*i+4*j+4))))};
 const pad=a=>a.flatMap((row,i)=>bits((row.reduce((v,x,j)=>v+x*ss[j],0)+ee[i]+1600)%16,4));
 const A=matrix(root),sig=bits(0xa5c3,16),masked=pad(A).map((v,i)=>v^sig[i]);
 ck(JSON.stringify(matrix(recovered.slice(0,8)))===JSON.stringify(A),"hidden matrix recovered");
 ck(JSON.stringify(masked.map((v,i)=>v^pad(matrix(recovered.slice(0,8)))[i]))===JSON.stringify(sig),"native capability recovered");
 for(let i=0;i<64;i++)for(let b=0;b<2;b++){let z=cap(b,10000+2*i+b);ck(attack(z)===b,"public bit opening");for(const w of val)ck(actual(z,w)===b,"correct every witness")}
 let partial=[...G];for(const f of fs)for(let mon=0;mon<M;mon++){let weight=mon.toString(2).replace(/0/g,"").length;if(weight<=2){let m=Array(M).fill(0);m[mon]=1;partial.push(mul(f,m))}}
 ck(partial.length===567&&rank(partial).r===61,"degree-two module closure saturates fixture");
 ck(rank([...partial,h]).r===62,"ghost removed from closure annihilator");
 const indicators=[];for(let a=0;a<M;a++)if(!val.includes(a)){let p=cn(1);for(let j=0;j<6;j++)p=mul(p,(a>>j)&1?unit(j):cn(1).map((v,i)=>v-unit(j)[i]));indicators.push(p)}
 ck(rank(indicators).r===61,"full ideal dimension=61");
 for(const row of indicators)for(const v of E)ck(dot(row,v)===0,"all valid evaluations annihilate ideal");
 return {run:"R53-GHOST-DUAL-IDEAL-CLOSURE-20261103",checks,original_assignments:val,original_mask_rank:R.r,ghost_h:[[0,1],[2,1],[8,1],[10,1],[32,-1],[33,-1]],ghost_norm:6,ghost_outside_witness_eval_span:true,source_bits_publicly_opened:seed.length,native_capability_publicly_recovered:true,degree2_closure_generators:partial.length,degree2_closure_rank:rank(partial).r,full_ideal_rank:rank(indicators).r,claim:"FINITE SOURCE BYPASS; NO GENERIC WKEM ADVANCE; NO QPT HARDNESS TEST"};
})();
console.log(JSON.stringify(result));
