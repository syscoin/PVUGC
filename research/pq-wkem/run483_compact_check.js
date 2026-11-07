// Run 483: exact deterministic functional checks only; no encrypted K or QPT implementation.
const crypto=require('crypto'), assert=require('assert');
let tests=0;
function ok(v){assert(v);tests++;}
function H(x){return crypto.createHash('sha256').update(x).digest();}
function enc(ctx,i,v){return Buffer.concat([Buffer.from('L483'),Buffer.from(ctx),Buffer.from([i,v])]);}
function leaf(ctx,i,v){return H(enc(ctx,i,v));}
function node(a,b){return H(Buffer.concat([Buffer.from('N483'),a,b]));}
function tree(ctx,vals){let h=vals.map((v,i)=>leaf(ctx,i,v));
  while(h.length<4)h.push(H(Buffer.from('PAD'+ctx+h.length)));
  const next=[node(h[0],h[1]),node(h[2],h[3])];
  return {root:node(next[0],next[1]).toString('hex'),open:i=>({i,v:vals[i],sib:[h[i^1].toString('hex'),next[Math.floor(i/2)^1].toString('hex')]})};}
function verify(ctx,root,o){if(!o||o.i<0||o.i>=3||![0,1].includes(o.v)||o.sib.length!==2)return false;
  let y=leaf(ctx,o.i,o.v),j=o.i;
  for(const s of o.sib){let b=Buffer.from(s,'hex');if(b.length!==32)return false;
    y=j&1?node(b,y):node(y,b);j>>=1;}
  return y.toString('hex')===root;}
const YES=[['XOR',[0,1]]], NO=[['NOT',[0]],['AND',[0,1]]];
function prove(ctx,C,w){let v=w.slice();for(const [op,ins] of C){let z=ins.map(i=>v[i]);v.push(op==='XOR'?z[0]^z[1]:op==='AND'?z[0]&z[1]:1-z[0]);}
  const t=tree(ctx,v);return {root:t.root,rows:C.map((g,j)=>({j,ins:g[1].map(i=>t.open(i)),out:t.open(w.length+j)})),final:t.open(v.length-1)};}
function admit(ctx,C,P){if(P.rows.length!==C.length)return false;
  for(let j=0;j<C.length;j++){let [op,ins]=C[j],r=P.rows[j];
    if(r.j!==j||r.ins.length!==ins.length||r.out.i!==(3-C.length+j))return false;
    if(r.ins.some((o,k)=>o.i!==ins[k]||!verify(ctx,P.root,o))||!verify(ctx,P.root,r.out))return false;
    let v=r.ins.map(o=>o.v),wanted=op==='XOR'?v[0]^v[1]:op==='AND'?v[0]&v[1]:1-v[0];
    if(r.out.v!==wanted)return false;}
  return P.final.i===2&&P.final.v===1&&verify(ctx,P.root,P.final);}
let accepted=0,rejected=0,skipped=0,replay=0;
for(let i=0;i<32;i++){
  let cy='R483|XOR|claim'+i,cn='R483|UNSAT|claim'+i;
  for(const w of [[0,0],[0,1],[1,0],[1,1]]){
    const p=prove(cy,YES,w),valid=(w[0]^w[1])===1;
    ok(admit(cy,YES,p)===valid);
    if(valid){accepted++;ok(!admit(cy+'|other',YES,p));replay++;}}
  for(const w of [[0],[1]]){
    let p=prove(cn,NO,w);ok(!admit(cn,NO,p));rejected++;
    p.rows.shift();ok(!admit(cn,NO,p));skipped++;}
  let a=tree(cn,[0,1,0]),b=tree(cn,[1,1,1]);
  ok(a.root!==b.root);
  ok((1-a.open(0).v)===a.open(1).v);
  ok((b.open(0).v & b.open(1).v)===b.open(2).v);
}
// A deliberately weak toy hash admits two contradictory leaf openings to one root.
function h8(x){return H(x)[0];}
const l0=h8(Buffer.from('toy0')),l1=h8(Buffer.from('toy1'));
let seen=new Map(),weak=null;
for(let s=0;s<256;s++)seen.set(h8(Buffer.from([l0,s])),s);
for(let s=0;s<256;s++){let r=h8(Buffer.from([l1,s]));if(seen.has(r)&&l0!==l1){weak={root:r,s0:seen.get(r),s1:s};break;}}
ok(weak!==null);
ok(h8(Buffer.from([l0,weak.s0]))===weak.root);
ok(h8(Buffer.from([l1,weak.s1]))===weak.root);
console.log(JSON.stringify({run:483,status:'PASS',assertions:tests,valid_streams:accepted,false_streams_rejected:rejected,skipped_rows_rejected:skipped,replays_rejected:replay,toy8_collision:weak,scope:'source admission only; protected key release unconstructed'},null,2));
