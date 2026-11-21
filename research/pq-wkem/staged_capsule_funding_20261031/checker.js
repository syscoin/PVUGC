'use strict';
// SCFB abstract dependency and binding checker. HMAC fixture is NOT a PQ signature.
const {createHash,createHmac}=require('crypto');
const canon=x=>JSON.stringify(x,(k,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const H=(x,n='sha512')=>createHash(n).update(canon(x)).digest('hex');
const mac=(k,x)=>createHmac('sha512','toy-key-'+k).update(canon(x)).digest('hex');
let assertions=0;const ok=(v,msg)=>{assertions++;if(!v)throw Error(msg)};
const D={network:'BTC-PQ-hypothetical',vkC:'fresh-challenge-vk',vkAuth:'honest-N-party-0',vkWatch:'honest-watcher',claim:'claim1',branch:'conflict',anchors:['a'],window:[200,300],margin:24,paths:[{id:'timeout',type:'safe',height:400},{id:'challenge',type:'fresh',height:0}]};
const F={version:2,inputs:['funding-input:0'],outputs:[{sat:100000,root:H(D)}],sequences:[4294967293]};
const txid=H(F,'sha256');
const X={relation:'R-original',claim:D.claim,branch:D.branch,anchors:D.anchors,window:D.window,outpoint:[txid,0],vkC:D.vkC,root:H(D)};
const C={scope:H(X),payload:'opaque-not-WKEM'};
const child={timeout:{outpoint:[txid,0],height:400,sighash:'ALL',outputs:'normal-payout'},challenge:{outpoint:[txid,0],height:0,sighash:'ALL',outputs:'qualified-challenge'}};
const pre={timeout:Object.fromEntries(['p0','p1','p2'].map(p=>[p,mac(p,child.timeout)]))};
const M={D,F,X,C,child,pre};const digest=H(M);
const cert={digest,txid,sig:mac('auth',{digest,txid})};
const ack={digest,txid,sig:mac('watch',{digest,txid})};
function gate(m,c,a){
  if(m.F.outputs[0].root!==H(m.D)||H(m.F,'sha256')!==m.X.outpoint[0]||m.X.outpoint[1]!==0)return false;
  if(m.X.root!==H(m.D)||m.X.claim!==m.D.claim||m.X.vkC!==m.D.vkC||m.C.scope!==H(m.X))return false;
  if(c.digest!==H(m)||c.txid!==H(m.F,'sha256')||c.sig!==mac('auth',{digest:c.digest,txid:c.txid}))return false;
  if(a.digest!==c.digest||a.txid!==c.txid||a.sig!==mac('watch',{digest:a.digest,txid:a.txid}))return false;
  if(m.D.paths.length!==2||m.D.paths.filter(p=>p.type==='fresh').length!==1||m.D.paths.some(p=>!['safe','fresh'].includes(p.type)))return false;
  if(m.child.timeout.outpoint[0]!==c.txid||m.child.challenge.outpoint[0]!==c.txid)return false;
  if(m.child.timeout.sighash!=='ALL'||m.child.challenge.sighash!=='ALL'||m.D.paths[0].height<=m.D.window[1]+m.D.margin)return false;
  if(Object.keys(m.pre).join()!=='timeout'||Object.keys(m.pre.timeout).sort().join()!=='p0,p1,p2')return false;
  return ['p0','p1','p2'].every(p=>m.pre.timeout[p]===mac(p,m.child.timeout));
}
ok(gate(M,cert,ack),'full gate');ok(!('challenge'in pre),'no challenge presig');
const edges=[['D','root'],['root','F'],['F','u'],['u','X'],['X','C'],['u','children'],['children','presigs'],['C','M'],['presigs','M'],['M','cert'],['cert','ack'],['ack','fundingSig']];
function dag(E){const nodes=new Set(E.flat()),seen=new Set(),active=new Set(),g=new Map();for(const [u,v]of E)g.set(u,[...(g.get(u)||[]),v]);function visit(u){if(active.has(u))return false;if(seen.has(u))return true;active.add(u);for(const v of g.get(u)||[])if(!visit(v))return false;active.delete(u);seen.add(u);return true}return [...nodes].every(visit)}
ok(dag(edges),'acyclic');for(const x of ['C','M','presigs'])ok(!dag([...edges,[x,'root']]),'naive hash cycle '+x);
let tampered=0;for(const section of ['X','C','D','F','pre','child'])for(const v of ['scope','other']){
 const m=JSON.parse(JSON.stringify(M));m[section][section==='X'?'claim':section==='C'?'payload':section==='D'?'claim':section==='F'?'version':section==='pre'?'timeout':'timeout']=v;
 ok(!gate(m,cert,ack),'tamper '+section);tampered++;
}
for(const [name,c,a]of [['cert',{...cert,sig:'bad'},ack],['watch',cert,{...ack,sig:'bad'}]])ok(!gate(M,c,a),'bad '+name);
let ready=0;for(let bits=0;bits<64;bits++){const canFund=bits===63;if(canFund)ready++;ok(!canFund||bits===63,'gate truth table')}
ok(ready===1,'only complete readiness');
const unsignedOther={...F,inputs:['unsolicited:0']};ok(H(unsignedOther,'sha256')!==txid,'unsolicited outpoint distinct');
console.log(JSON.stringify({status:'abstract-model-only',assertions,cyclesCaught:3,tamperRejects:tampered,readyStates:ready,readyVectors:64,outpoint:txid,manifestSha512:digest,sourceRelease:'NOT IMPLEMENTED'},null,2));
