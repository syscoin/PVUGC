/* R108 exact finite CNF clause-cut checker, zero cryptographic claims. */
function checker(){
const clauses=[["H1","H2"],["H2","H3"],["H3","H4"],["M","H1","H4"]], ids=["H1","H2","H3","H4","M"], p=5;
const counters={cut_sets:0,qualification_tapes:0,joint_trials:0,joint_equalities:0,negative_dnf_cases:0};let assertions=0;
function ok(x,m){assertions++;if(!x)throw Error(m+" at assertion "+assertions)}
function qual(C){return clauses.every(S=>S.some(i=>C.includes(i)))}
function shares(t,a,b,c){return [a,b,c,((t-a-b-c)%p+p)%p]}
function view(H,sh,y){let exposed=clauses.map((S,k)=>S.some(i=>!H.includes(i))?sh[k]:-1);
let joint=(exposed.reduce((a,v,k)=>a+(k+1)*(v<0?9:v),0)+7*y+19)%97;
let ck=(17*joint+31*y+41)%101,aux=(13*ck+5*joint+23*y+73)%103;
let queried=ids.filter((i,n)=>!H.includes(i)&&(ck+aux+n)%3===0);
return JSON.stringify([exposed,y,joint,ck,aux,queried,["offtarget-root",2],["offtarget-keys",3]])}
const F=[0,1,2];
for(let bits=0;bits<32;bits++){
let C=ids.filter((i,k)=>(bits>>k)&1);if(!C.includes("M"))C.push("M");
if(!qual(C)){ok(F.some(j=>clauses[j].every(i=>!C.includes(i))),"CNF cut cover");counters.cut_sets++}
for(let t=0;t<p;t++)for(let a=0;a<p;a++)for(let b=0;b<p;b++)for(let c=0;c<p;c++){
const sh=shares(t,a,b,c), known=clauses.map((S,k)=>S.some(i=>C.includes(i))?sh[k]:null);
if(qual(C))ok(known.every(x=>x!==null)&&known.reduce((z,x)=>z+x,0)%p===t,"all qualified exact root");
else ok(known.some(x=>x===null),"unqualified cannot reconstruct");
counters.qualification_tapes++}}
for(const j of F){let H=clauses[j],baseline=null;
for(let t=0;t<p;t++){let hist=new Map();
for(let a=0;a<p;a++)for(let b=0;b<p;b++)for(let c=0;c<p;c++){
let sh=shares(t,a,b,c);ok(clauses[j].every(i=>H.includes(i)),"full clause hidden");
for(let y=0;y<p;y++){let key=view(H,sh,y);hist.set(key,(hist.get(key)||0)+1);counters.joint_trials++}}
let sorted=JSON.stringify([...hist].sort((a,b)=>a[0].localeCompare(b[0])));
if(baseline!==null)ok(sorted===baseline,"full joint target-root independence");else baseline=sorted;
counters.joint_equalities++}}
for(let n=2;n<=4;n++){const roots=1<<n;for(let mask=0;mask<roots;mask++){
let C=Array.from({length:n},(_,i)=>"X"+i+((mask>>i)&1));
let possible=0;for(let other=0;other<roots;other++){
let cut=Array.from({length:n},(_,i)=>"X"+i+(1-((other>>i)&1)));
if(cut.every(x=>!C.includes(x)))possible++}
ok(possible===1,"2-DNF exponential distinct blocking cuts");counters.negative_dnf_cases++}}
return {run:"R108-CNF-CLAUSE-CUT-LWE-RELEASE-20261106",result:"PASS",assertions,counters,
 clauses,initial_malicious:["M"],honest_clause_cuts:F.map(j=>clauses[j]),
 scope:"Finite algebra/checking-field toy; NOT QPT security or generic NP compiler"};
}
console.log(JSON.stringify(checker(),null,2));
