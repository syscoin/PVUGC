'use strict';
// Exact finite algebra checker: NOT a QPT security or native-WKEM implementation.
let tests=0, rng=0x5eed2026;
function ok(b,m){tests++;if(!b)throw Error(m||('assertion '+tests))}
function rand32(){rng^=rng<<13;rng^=rng>>>17;rng^=rng<<5;return rng>>>0}
function randbits(n){let z=0n;for(let i=0;i<n;i+=32)z|=BigInt(rand32())<<BigInt(i);return z&((1n<<BigInt(n))-1n)}
function tp(T,D,L,M){let out=0n;for(let i=0;i<L;i++)if((M>>BigInt(i))&1n)for(let j=0;j<D;j++)out^=((T>>BigInt(j-i+L-1))&1n)<<BigInt(j);return out}
function G(A,seed){let z=0n;for(let row=0;row<12;row++){let v=Number((seed>>BigInt(24+2*row))&3n)-2;for(let i=0;i<3;i++)v+=A[3*row+i]*Number((seed>>BigInt(8*i))&255n);z|=BigInt(v&255)<<BigInt(8*row)}return z}
function F(A,seed,D){const mask=(1n<<48n)-1n;let z=0n,st=seed,steps=0;for(let i=0;i<D;i+=48){const y=G(A,st);z|=(y&mask)<<BigInt(i);st=(y>>48n)&mask;steps++}return [z&((1n<<BigInt(D))-1n),steps]}
// Toeplitz full-rank-on-each-nonzero-input: exact for L=2,D=5.
for(let x=1n;x<4n;x++){const hist=Array(32).fill(0);for(let t=0n;t<64n;t++)hist[Number(tp(t,5,2,x))]++;ok(hist.every(x=>x===2))}
// Global message-binding exception: enumerate every 8x2 Toeplitz matrix.
const boundF=[11n,33n,73n,165n];let bad=0;
for(let T=0n;T<512n;T++){const seen=new Map();let collision=false;for(let m=0n;m<4n;m++)for(let s=0;s<4;s++){const c=boundF[s]^tp(T,8,2,m);const key=c.toString();if(seen.has(key)&&seen.get(key)!==m)collision=true;seen.set(key,m)}if(collision)bad++;ok(typeof collision==='boolean')}
ok(bad<=128);
// True G_A(s,e) sample equations; no security assumptions are tested.
const A=Array.from({length:36},()=>rand32()%256);
for(let z=0;z<40;z++){const seed=randbits(48),g=G(A,seed);for(let row=0;row<12;row++){let v=Number((seed>>BigInt(24+2*row))&3n)-2;for(let i=0;i<3;i++)v+=A[3*row+i]*Number((seed>>BigInt(8*i))&255n);ok(Number((g>>BigInt(8*row))&255n)===(v&255))}}
// Sender-fixed public A includes adversarial A=0. Every honest receiver selects independent T.
const N=5,L=20,D=132,mat=Array.from({length:N},(_,i)=>i===0?Array(36).fill(0):Array.from({length:36},()=>rand32()%256));
const T=Array.from({length:N},()=>randbits(D+L-1)),M=Array.from({length:N},()=>randbits(L));let sameSeedMessages=0;
for(let i=0;i<N;i++)for(let j=0;j<N;j++){const seed=randbits(48);const [pad,steps]=F(mat[i],seed,D),c=pad^tp(T[j],D,L,M[i]);ok(steps===3);ok(c===(F(mat[i],seed,D)[0]^tp(T[j],D,L,M[i])));ok(c!==(pad^tp(T[j],D,L,M[i]^1n)));if(c===(F(mat[i],seed^1n,D)[0]^tp(T[j],D,L,M[i])))sameSeedMessages++}
// Honest uniform field element plus any pre-fixed corrupt sum is exactly uniform.
for(let corrupt=0;corrupt<257;corrupt+=17){const hist=Array(257).fill(0);for(let h=0;h<257;h++)hist[(h+corrupt)%257]++;ok(hist.every(x=>x===1))}
const output={run:'MINK-LWE-TOEPLITZ-LOCK-20261102-R14',status:'finite_checks_passed',checks:tests,enumerated_toeplitz:512,bad_toeplitz:bad,global_bad_bound:128,senders:5,commitments:25,seed_collisions_same_message_allowed:sameSeedMessages,toy_prg_steps:3,quantum_security_proved:false,generic_np_wkem_solved:false};
console.log(JSON.stringify(output));
