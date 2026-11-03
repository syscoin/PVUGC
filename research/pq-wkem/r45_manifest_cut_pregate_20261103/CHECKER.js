function checkR45(){
 let tests=0;const assert=(v,s)=>{tests++;if(!v)throw Error("R45 FAIL "+s);};
 const ser=e=>JSON.stringify([e.id,e.kind,e.earliest,e.input,e.dest,e.ctx,"ALL_INPUTS_OUTPUTS_LOCKTIME_AMOUNT_PREVOUT"]);
 const ctx="claim42|out:fund:0|fork-veto|anchors:A,B|window:0-60|vkH";
 const edge=(id,kind,earliest,dest,sealed)=>{let e={id,kind,earliest,input:"fund:0",dest,ctx,flags:"ALL",sealed,fullSigs:true,available:true,complete:true};e.signedMessage=ser(e);return e;};
 const good=()=>({ready:true,gate:true,nOfN:true,noAlt:true,noOtherSign:true,protectedSigner:true,sourceDA:true,fullTemplates:true,originalBound:true,deadline:60,cutoff:58,out:"fund:0",ctx,edges:[edge("challenge","challenge",0,"veto",true),edge("payout","timeout",61,"owner",false)]});
 const valid=m=>{
  if(![m.ready,m.gate,m.nOfN,m.noAlt,m.noOtherSign,m.protectedSigner,m.sourceDA,m.fullTemplates,m.originalBound].every(Boolean))return false;
  if(!Number.isInteger(m.deadline)||!Number.isInteger(m.cutoff)||m.cutoff<0||m.cutoff>m.deadline)return false;
  let ch=false,to=false,seen=new Set(),messages=new Set();
  if(!Array.isArray(m.edges))return false;
  for(let e of m.edges){
   if(seen.has(e.id)||messages.has(e.signedMessage)||!e.fullSigs||!e.available||!e.complete||e.flags!=="ALL"||e.input!==m.out||e.ctx!==m.ctx||!Number.isInteger(e.earliest)||e.earliest<0||e.signedMessage!==ser(e))return false;
   seen.add(e.id);messages.add(e.signedMessage);
   if(e.kind==="challenge"){if(!e.sealed||e.earliest>m.cutoff||e.dest!=="veto")return false;ch=true;}
   else if(e.kind==="timeout"){if(e.sealed||e.earliest<=m.deadline||e.dest!=="owner")return false;to=true;}
   else if(e.kind==="safe-refund"){if(e.sealed||e.dest!=="original-safe-owner")return false;}
   else return false;
  }
  return ch&&to;
 };
 assert(valid(good()),"good");
 const bad=[];
 const reject=(tag,f)=>{let m=good();f(m);assert(!valid(m),tag);bad.push(tag);};
 reject("early payout",m=>{m.edges[1].earliest=59;});
 reject("alternative key path",m=>{m.noAlt=false;});
 reject("funding gate absent",m=>{m.gate=false;});
 reject("signature not sealed",m=>{m.edges[0].sealed=false;});
 reject("challenge too late",m=>{m.edges[0].earliest=59;});
 reject("malicious sighash",m=>{m.edges[1].flags="SINGLE";});
 reject("transaction changed",m=>{m.edges[0].dest="attacker";});
 reject("wrong prevout",m=>{m.edges[0].input="other";});
 reject("wrong context",m=>{m.edges[0].ctx="other";});
 reject("missing source DA",m=>{m.sourceDA=false;});
 reject("funding ready false",m=>{m.ready=false;});
 reject("hidden sign",m=>{m.noOtherSign=false;});
 reject("original unbound",m=>{m.originalBound=false;});
 reject("incomplete N of N",m=>{m.nOfN=false;});
 reject("no challenge",m=>{m.edges.shift();});
 reject("no payout",m=>{m.edges.pop();});
 reject("unsafe refund",m=>{m.edges[0].kind="safe-refund";});
 let grid=0,allowed=0;
 for(let kind of ["timeout","challenge","safe-refund"])for(let t of [0,58,59,60,61,80]){
  let m=good(),dest=kind==="timeout"?"owner":kind==="challenge"?"veto":"original-safe-owner",e=edge("extra",kind,t,dest,kind==="challenge");
  m.edges.push(e);let expected=(kind==="timeout"&&t>60)||(kind==="challenge"&&t<=58)||kind==="safe-refund";
  assert(valid(m)===expected,"time grid "+kind+" "+t);grid++;if(expected)allowed++;
 }
 return {run:"R45-MANIFEST-CUT-PREGATE-20261103",tests,negative:bad.length,grid,allowed,scope:"abstract authenticated edge and one-honest signature reduction only",ORIGINAL:"UNSOLVED",QPT:"assumptions only",nativeBitcoinPQ:"CONDITIONAL"};
}
return checkR45();
