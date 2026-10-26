function checkFilteredNoise(){
 let n=0;const ok=(v,s)=>{if(!v)throw Error(s);n++};
 const parity=z=>{let b=0;while(z){z&=z-1;b^=1}return b};
 const NAND=[],AND=[];
 for(let a=0;a<2;a++)for(let b=0;b<2;b++)for(let c=0;c<2;c++){let t=(a<<2)|(b<<1)|c;if(c===1-(a&b))NAND.push(t);if(c===(a&b))AND.push(t)}
 function src(gates){
  let names=["one"],cols={one:0};
  for(let i=0;i<3;i++)for(let b=0;b<2;b++){let k="v"+i+b;cols[k]=names.length;names.push(k)}
  for(let f=0;f<gates.length;f++)for(const a of gates[f]){let k="f"+f+"_"+a;cols[k]=names.length;names.push(k)}
  let rows=[];
  for(let i=0;i<3;i++)rows.push(1|(1<<cols["v"+i+0])|(1<<cols["v"+i+1]));
  for(let f=0;f<gates.length;f++){
   let r=1;for(const a of gates[f])r|=1<<cols["f"+f+"_"+a];rows.push(r);
   for(let i=0;i<3;i++)for(let b=0;b<2;b++){
    let z=1<<cols["v"+i+b];for(const a of gates[f])if(((a>>(2-i))&1)===b)z|=1<<cols["f"+f+"_"+a];rows.push(z)
   }
  }
  const piv=new Map();
  for(let r of rows){while(r){let j=31-Math.clz32(r);if(!piv.has(j)){piv.set(j,r);break}r^=piv.get(j)}}
  const bases=[];
  for(let j=0;j<names.length;j++)if(!piv.has(j)){
   let v=1<<j;for(const [pj,r] of [...piv.entries()].sort((x,y)=>x[0]-y[0]))if(parity(r&v))v^=1<<pj;
   ok(rows.every(r=>!parity(r&v)),"source kernel");bases.push(v)
  }
  function character(a){let v=0;for(let i=0;i<bases.length;i++)if((a>>i)&1)v^=bases[i];return v}
  function facMask(f,v){let m=0;for(let j=0;j<gates[f].length;j++)if((v>>cols["f"+f+"_"+gates[f][j]])&1)m|=1<<j;return m}
  return {rows,cols,bases,character,facMask,rank:piv.size,m:names.length}
 }
 const fs=src([NAND,AND]),ts=src([NAND,NAND]);
 ok(fs.m===15&&fs.rank===11&&fs.bases.length===4,"false fixture rank");
 ok(ts.m===15&&ts.rank===11&&ts.bases.length===4,"true fixture rank");
 const phi=[3,2,1,0,-1],wt=z=>z.toString(2).replaceAll("0","").length;
 const spectrum=S=>Array.from({length:16},(_,a)=>{let v=S.character(a);return {bit:v&1,num:phi[wt(S.facMask(0,v))]*phi[wt(S.facMask(1,v))]}});
 const F=spectrum(fs),T=spectrum(ts);let odd=0;
 for(let a=0;a<16;a++)if(F[a].bit){odd++;let v=fs.character(a),s=[wt(fs.facMask(0,v)),wt(fs.facMask(1,v))];ok(s.every(z=>z%2===1)&&s.some(z=>z===3),"triple factor exists");ok(F[a].num===0,"all odd false characters killed")}
 ok(odd===8,"eight sensitive false characters");let eq=true;
 for(let x=0;x<2;x++){let total=0;for(let q=0;q<16;q++){
   let v=0,base=0;for(let a=0;a<16;a++){v+=F[a].num*(parity(a&q)^(x&F[a].bit)?-1:1);base+=F[a].num*(parity(a&q)?-1:1)}
   ok(v>=0,"positive Q probability");ok(v===base,"EXACT conditional Q equality");total+=v;eq&&=v===base
  }ok(total===144,"Q probabilities normalize")
 }
 ok(eq,"full false quotient equality");let valid=0;
 for(let a=0;a<8;a++){if(!NAND.includes(a))continue;let bits=[a>>2&1,a>>1&1,a&1],v=1;
  for(let i=0;i<3;i++)v|=1<<ts.cols["v"+i+bits[i]];
  for(let f=0;f<2;f++)v|=1<<ts.cols["f"+f+"_"+a];
  ok(ts.rows.every(r=>!parity(r&v)),"true witness SOURCE");
  ok(wt(ts.facMask(0,v))===1&&wt(ts.facMask(1,v))===1,"true factor onehot");valid++
 }
 ok(valid===4,"four distinct witnesses");ok(T.some(z=>z.bit&&z.num!==0),"true X signal");
 let den=0,one=0;for(let e=0;e<128;e++){let w=Math.max(7-2*wt(e),0);den+=w;one+=(parity(e&1)?-1:1)*w}
 ok(den===140&&one===64,"d7 rho=16/35");
 for(let mask=1;mask<128;mask++)if(wt(mask)>=3&&wt(mask)%2===1){
  let sum=0;for(let e=0;e<128;e++)sum+=(parity(e&mask)?-1:1)*Math.max(7-2*wt(e),0);
  ok(sum===0,"all d7 higher odd coefficients zero")
 }
 return JSON.stringify({name:"FOURIER_FILTER_GATE_EXACT_JS_20261026",status:"PASS",assertions:n,false_odd_characters_killed:odd,all_32_false_full_quotient_probabilities_equal:eq,true_distinct_original_witnesses:valid,rho4:"2/3",rho7:"16/35",disclaimer:"not a generic PPT WKEM; hard true key->ORIGINAL extraction unresolved"},null,2)+"\n";
}
globalThis.WKEM_FILTER_CHECK_OUTPUT=checkFilteredNoise();
if(typeof console!=="undefined"&&console.log)console.log(globalThis.WKEM_FILTER_CHECK_OUTPUT);
