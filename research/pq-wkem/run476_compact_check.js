'use strict';
const crypto=require('crypto');
let checks=0;
function ok(x){checks++;if(!x)throw Error('assertion '+checks)}
const contexts=['claim77/utxoA/challenge','claim77/utxoA/disprove','claim78/utxoB/disprove','claim77/utxoA/normal'];
function sha(s){return crypto.createHash('sha256').update(s).digest('hex')}
function hash(c,t){return sha('RUN476/context/'+c+'/'+t.toString(16).padStart(3,'0'))}
function R(i,w){return i===0 && (w==='A'||w==='B')}
function Verify(i,h,tag,data){return tag===0?R(i,data):tag===1&&Number.isInteger(data)&&data>=0&&data<4096&&hash(contexts[i],data)===h}
const cases=[];
for(let i=0;i<contexts.length;i++){
 const t=parseInt(sha('RUN476/private/'+contexts[i]).slice(0,3),16),h=hash(contexts[i],t);
 const witnesses=['A','B','bad'].filter(w=>R(i,w));
 ok(witnesses.length===(i===0?2:0));ok(Verify(i,h,1,t));
 for(const w of ['A','B','bad'])ok(Verify(i,h,0,w)===R(i,w));
 const found=[];for(let j=0;j<4096;j++){if(hash(contexts[i],j)===h)found.push(j);ok(Verify(i,h,1,j)===(hash(contexts[i],j)===h))}
 ok(found.length===1&&found[0]===t);
 cases.push({context:contexts[i],original_witnesses:witnesses.length,proof_existence:true,first_bruteforce_query:t+1});
}
for(let i=0;i<4;i++)for(let j=0;j<4;j++)if(i!==j){
 const t=parseInt(sha('RUN476/private/'+contexts[i]).slice(0,3),16);
 const u=parseInt(sha('RUN476/private/'+contexts[j]).slice(0,3),16);
 ok(!Verify(j,hash(contexts[j],u),1,t));
}
console.log(JSON.stringify({run:476,status:'PASS',checks,cases,toy_bits:12,conclusion:'computational proof soundness is not semantic false-instance nonmembership',qpt_security:'UNPROVED; finite semantic diagnostic only'},null,2));
