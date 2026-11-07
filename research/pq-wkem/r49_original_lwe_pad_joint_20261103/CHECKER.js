function checkR49(){
  let assertions=0, opened=0, falseCouplings=0;const eq=(a,b,m)=>{if(JSON.stringify(a)!==JSON.stringify(b))throw Error(m);assertions++};const yes=(x,m)=>{if(!x)throw Error(m);assertions++};
  function inv(a,q){for(let i=1;i<q;i++)if((a*i)%q===1)return i;throw Error("inv");}
  function indicator(n,active,v){let a=Array(1<<n).fill(0);a[0]=1;for(let i=0;i<active;i++){const b=Array(1<<n).fill(0);for(let j=0;j<a.length;j++)if(v&(1<<i))b[j|(1<<i)]+=a[j];else{b[j]+=a[j];b[j|(1<<i)]-=a[j];}a=b}return a}
  function mul(a,b,q){let c=Array(a.length).fill(0);for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++)c[i|j]=((c[i|j]+a[i]*b[j])%q+q)%q;return c}
  function quotient(n,active,q,forbid){
    const fs=forbid.map(v=>indicator(n,active,v)),M=1<<n;let rows=[];
    for(let i=0;i<fs.length;i++)for(let j=i;j<fs.length;j++)rows.push(mul(fs[i],fs[j],q));
    rows=rows.filter(r=>r.some(v=>v!==0)).map(r=>r.map(v=>(v%q+q)%q));let piv=[],k=0;
    for(let c=0;c<M;c++){let h=rows.findIndex((r,i)=>i>=k&&r[c]);if(h<0)continue;
      [rows[k],rows[h]]=[rows[h],rows[k]];let f=inv(rows[k][c],q);rows[k]=rows[k].map(x=>x*f%q);
      for(let j=0;j<rows.length;j++)if(j!==k&&rows[j][c]){let t=rows[j][c];rows[j]=rows[j].map((v,i)=>(v-t*rows[k][i]%q+q)%q)}
      piv.push(c);if(++k===rows.length)break;
    }
    rows=rows.slice(0,k);const free=Array.from({length:M},(_,i)=>i).filter(i=>!piv.includes(i));
    function project(a){a=a.map(v=>(v%q+q)%q);for(let i=0;i<piv.length;i++){let t=a[piv[i]];if(t)a=a.map((v,j)=>(v-t*rows[i][j]%q+q)%q)}return free.map(i=>a[i]);}
    function lift(z){const a=Array(M).fill(0);free.forEach((p,i)=>a[p]=z[i]);return a}
    function ev(z,w){return lift(z).reduce((sum,v,i)=>((i&~w)===0?sum+v:sum),0)%q}
    function dec(z,w){let v=ev(z,w),D=(q-1)/2,d=x=>Math.min((v-x+q)%q,(x-v+q)%q);return +(d(D)<d(0))}
    function enc(bit,error){let a=error.slice();a[0]+=(q-1)/2*bit;return project(a)}
    return {M,rows,piv,free,project,ev,dec,enc};
  }
  let rngstate=49;function rnd(){rngstate=(Math.imul(rngstate,1664525)+1013904223)>>>0;return rngstate}
  const f=quotient(3,2,257,[0,1,2,3]),t=quotient(3,2,257,[0,1,2]);
  eq([f.piv.length,f.free.length,t.piv.length,t.free.length],[4,4,3,5],"rank");
  yes(f.project([1,0,0,0,0,0,0,0]).every(v=>v===0),"FALSE constant in W");
  for(let w of [3,7])for(let r of t.rows)eq(t.ev(t.project(r),w),0,"true vanishing");
  function bits(x,n){return Array.from({length:n},(_,i)=>(x>>(n-1-i))&1)}
  const q=16,nn=2,m=3,AA=Array.from({length:m},()=>Array.from({length:nn},()=>rnd()%q));
  const seed=(s,e)=>[...s.flatMap(v=>bits(v,4)),...e.map(v=>v+1)];
  const pad=(s,e)=>AA.map((row,i)=>((row.reduce((v,a,j)=>v+a*s[j],0)+e[i])%q+q)%q).flatMap(v=>bits(v,4));
  const sample=()=>({s:Array.from({length:nn},()=>rnd()%q),e:Array.from({length:m},()=>-1+(rnd()%2))});
  const noise=()=>Array.from({length:8},()=>rnd()%3-1);
  let target=sample(),K=seed(target.s,target.e),Y=pad(target.s,target.e),sigma=Array.from({length:12},()=>rnd()%2),D=Y.map((v,i)=>v^sigma[i]),Kbind=Array.from({length:8},()=>rnd()%2);
  let Zp=K.map(b=>t.enc(b,noise())),Zb=Kbind.map(b=>t.enc(b,noise()));
  function ck(bind,z1,z2,d){return JSON.stringify(["R49",bind,z1,z2,d,AA,"relation","UTXO","branch","native_vk"])}
  let checkingKey=ck(Kbind,Zb,Zp,D);
  for(let w of [3,7]){let v=Zp.map(z=>t.dec(z,w)),kb=Zb.map(z=>t.dec(z,w));
    eq(v,K,"original-witness seed");eq(kb,Kbind,"original-witness binding seed");
    let s=Array.from({length:nn},(_,i)=>v.slice(i*4,(i+1)*4).reduce((a,x)=>a*2+x,0)),e=v.slice(8).map(x=>x-1);
    eq(pad(s,e),Y,"original-witness pad");eq(D.map((x,i)=>x^pad(s,e)[i]),sigma,"original-witness native signature");
    eq(ck(kb,Zb,Zp,D),checkingKey,"original-witness CK");opened++;
  }
  for(let j=0;j<128;j++){let a=sample(),b=sample(),ka=seed(a.s,a.e),kb=seed(b.s,b.e),errors=ka.map(()=>noise());
    let za=ka.map((v,i)=>f.enc(v,errors[i])),zb=kb.map((v,i)=>f.enc(v,errors[i]));
    eq(za,zb,"same FALSE capsules for unrelated LWE challenge seeds");
    let sourceWithoutSeed=errors.map(e=>f.project(e));eq(za,sourceWithoutSeed,"LWE-challenge simulator without seed");
    let la=pad(a.s,a.e).map((v,i)=>v^sigma[i]),eck=ck(Kbind,Zb,za,la);
    eq(eck,ck(Kbind,Zb,sourceWithoutSeed,la),"exact FULL public CK embedding");
    falseCouplings++;
  }
  eq([16*256+4*4096,65536*45,20480*45,4096*256*2],[20480,2949120,921600,2097152],"resource accounting");
  return {run:"R49-ORIGINAL-LWE-PAD-JOINT-20261103",assertions,distinct_original_witnesses_opened:opened,false_capsule_and_full_ck_couplings:falseCouplings,
   toy:{lwe_modulus:16,lwe_n:2,lwe_m:3,lwe_seed_bits:11,lwe_output_bits:12},
   illustrative_not_security_sized:{signature_bits:65536,source_codom:15,source_coeff_bytes:3,lwe_seed_bits:20480,raw_pad_capsule_bytes:2949120,lwe_pad_capsule_bytes:921600,public_A_bytes:2097152,
    unamortized_total_raw_with_bind_and_D:2968832,unamortized_total_lwe_with_bind_D_A:3038464},
   quantum_hardness:"NOT TESTED",hard_true_original_extraction:"NOT PROVED"};
}
const first=checkR49(),second=checkR49();if(JSON.stringify(first)!==JSON.stringify(second))throw Error('repeat failed');
console.log(JSON.stringify({result:first,repeat_identical:true},null,2));
