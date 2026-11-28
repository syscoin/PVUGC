function checkR51(){
  let assertions=0, opened=0, falseCases=0;
  const ok=(p,m)=>{if(!p)throw Error(m);assertions++;};
  const eq=(a,b,m)=>ok(JSON.stringify(a)===JSON.stringify(b),m);
  const q=257;
  function inv(a){for(let i=1;i<q;i++)if((a*i)%q===1)return i;throw Error("non-unit");}
  function indicator(v){let a=Array(8).fill(0);a[0]=1;for(let j=0;j<2;j++){const b=Array(8).fill(0);for(let i=0;i<8;i++){if(v&(1<<j))b[i|(1<<j)]+=a[i];else{b[i]+=a[i];b[i|(1<<j)]-=a[i];}}a=b;}return a;}
  function mul(a,b){let c=Array(8).fill(0);for(let i=0;i<8;i++)for(let j=0;j<8;j++)c[i|j]=((c[i|j]+a[i]*b[j])%q+q)%q;return c;}
  function quotient(forbid){
    const f=forbid.map(indicator), rows=[];
    for(let i=0;i<f.length;i++)for(let j=i;j<f.length;j++)rows.push(mul(f[i],f[j]));
    let k=0,piv=[];
    for(let c=0;c<8;c++){let h=rows.findIndex((r,i)=>i>=k&&r[c]!==0);if(h<0)continue;
      [rows[k],rows[h]]=[rows[h],rows[k]];let u=inv(rows[k][c]);rows[k]=rows[k].map(v=>v*u%q);
      for(let j=0;j<rows.length;j++)if(j!==k&&rows[j][c]){let t=rows[j][c];rows[j]=rows[j].map((v,i)=>(v-t*rows[k][i]%q+q)%q);}
      piv.push(c);if(++k===rows.length)break;
    }
    const free=Array.from({length:8},(_,i)=>i).filter(i=>!piv.includes(i));
    function P(input){let a=input.map(v=>(v%q+q)%q);for(let i=0;i<k;i++){const t=a[piv[i]];if(t)a=a.map((v,j)=>(v-t*rows[i][j]%q+q)%q);}return free.map(i=>a[i]);}
    function Ev(z,w){const a=Array(8).fill(0);free.forEach((j,i)=>a[j]=z[i]);return a.reduce((s,v,i)=>((i&~w)===0?s+v:s),0)%q;}
    function enc(bit,noise){let a=noise.slice();a[0]+=128*bit;return P(a);}
    function dec(z,w){const v=Ev(z,w),d=t=>Math.min((v-t+q)%q,(t-v+q)%q);return +(d(128)<d(0));}
    return {P,Ev,enc,dec,rank:k,codim:free.length,rows:rows.slice(0,k)};
  }
  const t=quotient([0,1,2]),f=quotient([0,1,2,3]);
  eq([t.rank,t.codim,f.rank,f.codim],[3,5,4,4],"quotient rank");
  eq(f.P([1,0,0,0,0,0,0,0]),[0,0,0,0],"FALSE P(1)=0");
  for(const w of [3,7])for(const r of t.rows)eq(t.Ev(t.P(r),w),0,"valid ORIGINAL evaluator annihilates W");
  function bits(n,w){return Array.from({length:w},(_,j)=>(n>>(w-j-1))&1);}
  const G=r=>Array.from({length:3},(_,i)=>Array.from({length:2},(_,j)=>((r*17+13*i+29*j+(i*j)*7)>>>0)%16));
  const encode=(r,s,e)=>[...bits(r,8),...s.flatMap(a=>bits(a,4)),...e.map(v=>v+1)];
  const parse=k=>({r:k.slice(0,8).reduce((a,b)=>2*a+b,0),
    s:[k.slice(8,12).reduce((a,b)=>2*a+b,0),k.slice(12,16).reduce((a,b)=>2*a+b,0)],e:k.slice(16).map(v=>v-1)});
  const y=(A,s,e)=>A.map((row,i)=>(row.reduce((v,a,j)=>v+a*s[j],0)+e[i]+1600)%16).flatMap(v=>bits(v,4));
  const noise=i=>Array.from({length:8},(_,j)=>(i*5+j*7)%3-1);
  const r=173,s=[7,12],e=[-1,0,0],A=G(r),k=encode(r,s,e),kb=[1,0,1,0];
  const Z=k.map((v,i)=>t.enc(v,noise(i))),Zb=kb.map((v,i)=>t.enc(v,noise(i+900)));
  const sig=Array.from({length:12},(_,i)=>(i*7+3)%2),D=y(A,s,e).map((a,i)=>a^sig[i]);
  const alpha=JSON.stringify(["commit-to-A",A]);const publicView={alpha,D,Z,Zb,claim:"UTXO-claim",branch:"challenge",vk:"conditional-native"};
  const CK=JSON.stringify(["CK",kb,publicView]);
  for(const w of [3,7]){
    const recovered=Z.map(z=>t.dec(z,w)),bind=Zb.map(z=>t.dec(z,w));
    eq(recovered,k,"same hidden A+LWE seed for distinct ORIGINAL witnesses");eq(bind,kb,"same bind seed");
    const parsed=parse(recovered),A1=G(parsed.r);
    eq(A1,A,"reconstructed A");eq(JSON.stringify(["commit-to-A",A1]),alpha,"A commitment");
    eq(y(A1,parsed.s,parsed.e).map((v,i)=>v^D[i]),sig,"same native pre-signature");
    eq(JSON.stringify(["CK",bind,publicView]),CK,"secret-correlated public checking key");opened++;
  }
  for(let z=0;z<64;z++){
    const k1=encode(z+40,[z%16,(3*z)%16],[-1,z%2,0]);
    const k2=encode(z+110,[(z+1)%16,(7*z)%16],[0,z%2-1,-1]);
    const a=k1.map((bit,i)=>f.enc(bit,noise(1000+z*23+i)));
    const b=k2.map((bit,i)=>f.enc(bit,noise(1000+z*23+i)));
    eq(a,b,"entire FALSE seed capsules independent of both hidden seeds");
    eq(a,k1.map((_,i)=>f.P(noise(1000+z*23+i))),"FALSE simulator without source secrets");
    const fixed={alpha,D,claim:"certFALSE",Z:a};
    eq(JSON.stringify(["CK",kb,fixed]),JSON.stringify(["CK",kb,{...fixed,Z:b}]),"full secret-correlated CK conditional equality");
    falseCases++;
  }
  const sourceBytes=(20480+256+256)*45,total=sourceBytes+8192+48;
  eq([sourceBytes,total,3038464,2968832],[944640,952880,3038464,2968832],"correct resource accounting");
  ok(total<3038464&&total<2968832,"one-claim capsule+matrix total smaller");
  ok(JSON.stringify(G(r))===JSON.stringify(A),"NEGATIVE CONTROL: published PRG seed would permit matrix recomputation");
  return {name:"R51-HIDDEN-A-ORIGINAL-PRG-JOINT-20261103",assertions,opened_original_witnesses:opened,
    certfalse_seed_and_ck_couplings:falseCases,public_matrix_seed:"NOT PUBLISHED",
    toy_expander:"NOT cryptographically secure; SHAKE256 expansion separately executed in local Python checker",
    resource_bytes:{R49:3038464,R48:2968832,R51:total},hard_true_original_extraction:"UNPROVED",QPT_hardness:"NOT TESTED"};
}
const first=checkR51(),second=checkR51();if(JSON.stringify(first)!==JSON.stringify(second))throw Error('repeat mismatch');
console.log(JSON.stringify({result:first,repeat_identical:true},null,2));
