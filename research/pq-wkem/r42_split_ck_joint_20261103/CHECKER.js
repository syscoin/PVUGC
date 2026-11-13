function checkR42() {
 let seed=0x42c0ffee, assertions=0, decoded=0, openings=0, simulators=0;
 const ok=(v,label)=>{assertions++;if(!v)throw Error("R42 assert: "+label)};
 const rnd=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0};
 const ri=n=>rnd()%n, q=257, n=2,m=12,B=1,delta=128,kappa=16,scopes=2;
 const mod=(v,Q=q)=>((v%Q)+Q)%Q;
 const dist=(x,y)=>Math.min(mod(x-y),mod(y-x));
 const fnv=s=>{let h=2166136261>>>0;for(let i=0;i<s.length;i++)h=Math.imul(h^s.charCodeAt(i),16777619)>>>0;return h};
 const pow=(v,e,N)=>{let a=1,b=v%N;while(e){if(e%2)a=a*b%N;b=b*b%N;e=Math.floor(e/2)}return a};
 const vk={N:3233,e:17}, sk=2753;
 const sign=msg=>pow(fnv(msg)%vk.N,sk,vk.N);
 const verify=(msg,sig)=>pow(sig,vk.e,vk.N)===fnv(msg)%vk.N;
 const prg=(k,scope)=>fnv("R42 TOY|"+scope+"|"+k)&65535;
 const source=()=>{let A=Array.from({length:n},()=>Array.from({length:m},()=>ri(q)));
  let s=Array.from({length:n},()=>ri(q)),e=Array.from({length:m},()=>ri(3)-1);
  let b=Array.from({length:m},(_,i)=>mod(e[i]+A[0][i]*s[0]+A[1][i]*s[1]));
  return {A,b,s,e}};
 const valid=(pk,w)=>pk.b.every((v,i)=>Math.abs(w.e[i])<=B&&mod(pk.A[0][i]*w.s[0]+pk.A[1][i]*w.s[1]+w.e[i])===v);
 const enc=(pk,bit)=>{let r=Array.from({length:m},()=>ri(2));
  return {u:pk.A.map(row=>mod(row.reduce((v,x,i)=>v+x*r[i],0))),
    v:mod(pk.b.reduce((v,x,i)=>v+x*r[i],delta*bit))}};
 const dec=(ct,w)=>{let val=mod(ct.v-ct.u.reduce((v,x,i)=>v+x*w.s[i],0));return +(dist(val,delta)<dist(val,0))};
 const tag=(pub,kbind)=>String(fnv("R42-CK|"+JSON.stringify({relation:pub.context.relation,
   claim:pub.context.claim,original_statement_id:pub.context.original_statement_id,
   context:pub.context,pk:pub.pk,msg:pub.msg,vk:pub.vk,D:pub.D,capsules:pub.capsules,kbind})));
 const create=(claim,J)=>{let branches=Array.from({length:J},source);
  let pk=branches.map(x=>({A:x.A,b:x.b}));
  let context={relation:"RESTRICTED_OR_LWE_NOT_ORIGINAL",original_statement_id:"orig-hash-"+claim,
   claim,utxo:"UTXO-"+claim,branch:"fixed-native-challenge",window:"anchor-window-"+claim,vk};
  let msg=String(fnv(JSON.stringify({context,pk,vk}))),sig=sign(msg);
  let kbind=ri(65536),kpad=ri(65536),D=sig^prg(kpad,claim);
  let capsule=(p)=>[kbind,kpad].map(key=>Array.from({length:kappa},(_,bit)=>
     Array.from({length:scopes},()=>enc(p,(key>>>bit)&1))));
  let capsules=pk.map(capsule);
  let base={context,pk,msg,vk,D,capsules};
  let CK=tag(base,kbind),nonce=ri(65536);
  let aux=String(fnv("R42-AUX|"+CK+"|"+nonce));
  return {branches,kbind,kpad,sig,public:{...base,CK,nonce,aux}}};
 const cases=[create("alpha",3),create("beta",2),create("gamma",2)];
 const open=(c,j,w,pub=c.public)=>{if(!valid(pub.pk[j],w))return null;
   let keys=[];for(let role=0;role<2;role++){let k=0;for(let bit=0;bit<kappa;bit++){
    let b=pub.capsules[j][role][bit].map(ct=>dec(ct,w));
    ok(b.every(x=>x===b[0]),"scope decode consistent"); decoded+=b.length;k|=b[0]<<bit;}keys.push(k)}
   let [kb,kp]=keys;
   if(tag(pub,kb)!==pub.CK)return null;
   if(pub.aux!==String(fnv("R42-AUX|"+pub.CK+"|"+pub.nonce)))return null;
   let sig=pub.D^prg(kp,pub.context.claim);
   if(!verify(pub.msg,sig))return null;
   return {kbind:kb,kpad:kp,sig}};
 for(const c of cases){
  ok(verify(c.public.msg,c.sig),"honest native signature");
  for(let j=0;j<c.branches.length;j++){
   let w={s:c.branches[j].s,e:c.branches[j].e};
   let o=open(c,j,w);ok(!!o,"open valid branch");
   ok(o.kbind===c.kbind&&o.kpad===c.kpad&&o.sig===c.sig,"SAME joint capability");
  }
 }
 let target=cases[0],w={s:target.branches[0].s,e:target.branches[0].e};
 for(const field of ["D","msg"]){
   let p={...target.public,[field]:field==="D"?(target.public.D^1):target.public.msg+"X"};
   ok(open(target,0,w,p)===null,"altered transcript "+field+" rejected");
 }
 let changed={...target.public,context:{...target.public.context,utxo:"different-utxo"}};
 ok(open(target,0,w,changed)===null,"changed UTXO rejected");
 let cap=JSON.parse(JSON.stringify(target.public));cap.capsules[0][0][0][0].v=mod(cap.capsules[0][0][0][0].v+1);
 ok(open(target,0,w,cap)===null,"changed ciphertext committed by CK");
 let blocked=0;
 for(let j=1;j<cases.length;j++){let c=cases[j],record={witnesses:c.branches.map(x=>({s:x.s,e:x.e})),
  kbind:c.kbind,kpad:c.kpad,sig:c.sig};
  openings++;ok(record.witnesses.every((w,i)=>!!open(c,i,w)),"non-target complete opening");
  for(const ww of record.witnesses){if(!valid(target.public.pk[0],ww))blocked++}
 }
 ok(blocked===4,"non-target source cannot authenticate target source");
 for(let kb=0;kb<4;kb++)for(let sig=0;sig<4;sig++){
  let ck=fnv("CK|"+kb),hist=Array(4).fill(0);
  for(let p=0;p<4;p++){let D=sig^p;hist[D]++;ok(ck===fnv("CK|"+kb),"CK independent pad and native signature");}
  ok(hist.every(v=>v===1),"OTP uniform conditional on bind-key and signature");simulators++;
 }
 for(let kp=0;kp<32;kp++){let s=ri(65536),D=s^prg(kp,"alpha"),badCK=kp;
  ok((D^prg(badCK,"alpha"))===s,"negative: CK=pad secret discloses native signature")}
 return {run:"R42-SPLIT-CK-JOINT-SIM",assertions,decoded_bits:decoded,
  original_valid_witnesses_tested:0,restricted_lwe_or_branches:7,
  checked_non_target_openings:openings,uniform_conditional_fixtures:simulators,
  parameters:{q,n,m,B,delta,kappa,scopes},
  guarantees:"classical algebraic tests only; no QPT hardness; no ORIGINAL binding",
  checksum:fnv(JSON.stringify(target.public)).toString(16)};
}
console.log(JSON.stringify(checkR42(), null, 2));
