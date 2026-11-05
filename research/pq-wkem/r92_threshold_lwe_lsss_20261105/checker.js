function checker(){
 let tests=0,C={authorized:0,unauthorized:0,finite:0,field:0,efficiency:0};
 function ok(v,d){tests++;if(!v)throw Error("assert "+tests+" "+d)}
 function mul(a,b){let z=0;while(b){if(b&1)z^=a;a<<=1;if(a&256)a^=0x11b;b>>=1;}return z}
 function pow(a,e){let y=1;for(;e;e>>=1,a=mul(a,a))if(e&1)y=mul(y,a);return y}
 function inv(a){if(!a)throw Error("zero inverse");return pow(a,254)}
 let state=0x9262026;function rnd(){state=(Math.imul(state,1664525)+1013904223)>>>0;return state&255}
 for(let a=1;a<256;a++){ok(mul(a,inv(a))===1,"GF256 inverse");C.field++}
 function share(T,k,n){let poly=T.map(v=>[v,...Array.from({length:k-1},rnd)]),ss={};for(let i=1;i<=n;i++)ss[i]=poly.map(cs=>cs.reduce((sum,c,j)=>sum^mul(c,pow(i,j)),0));return ss}
 function open(S,U){return S[U[0]].map((_,b)=>U.reduce((sum,i)=>{let weight=1;for(const j of U)if(j!==i)weight=mul(weight,mul(j,inv(i^j)));return sum^mul(S[i][b],weight)},0))}
 function rank(U,k){const rows=U.map(i=>Array.from({length:k-1},(_,j)=>pow(i,j+1)));let r=0;for(let col=0;col<k-1&&r<rows.length;col++){let p=r;while(p<rows.length&&!rows[p][col])p++;if(p===rows.length)continue;[rows[p],rows[r]]=[rows[r],rows[p]];const z=inv(rows[r][col]);rows[r]=rows[r].map(x=>mul(x,z));for(let h=0;h<rows.length;h++)if(h!==r&&rows[h][col]){const a=rows[h][col];rows[h]=rows[h].map((x,j)=>x^mul(a,rows[r][j]))}r++}return r}
 for(let k=2;k<=5;k++){let n=k+2;for(let trial=0;trial<8;trial++){const T=Array.from({length:8},rnd),S=share(T,k,n);for(let mask=0;mask<(1<<n);mask++){const U=[];for(let i=1;i<=n;i++)if(mask&(1<<(i-1)))U.push(i);if(U.length>=k){ok(JSON.stringify(open(S,U))===JSON.stringify(T),"all k-of-n open same T");C.authorized++}else{ok(rank(U,k)===U.length,"unauthorized masks full rank");C.unauthorized++}}}}
 const mod=5;for(let mask=0;mask<16;mask++){const U=[1,2,3,4].filter((_,j)=>mask&(1<<j));if(U.length>=3)continue;let baseline=null;for(let t=0;t<5;t++){const cnt={};for(let a=0;a<5;a++)for(let b=0;b<5;b++){let key=U.map(i=>(t+a*i+b*i*i)%5).join(",");cnt[key]=(cnt[key]||0)+1}const stable=JSON.stringify(Object.entries(cnt).sort(([a],[b])=>a.localeCompare(b)));if(baseline===null)baseline=stable;ok(stable===baseline,"all roots same unauthorized joint GF5 law");C.finite++}}
 const n=16,k=8,choose=(n,r)=>{let v=1;for(let j=1;j<=r;j++)v=v*(n-j+1)/j;return v};ok(k*choose(n,k)===102960&&k*choose(n,k)/n===6435,"DNF source occurrence reduction");C.efficiency++;
 return {run:"R92-THRESHOLD-LWE-LSSS-20261105",status:"RESTRICTED_CONSTRUCTIVE_ADVANCE_NOT_GENERIC_WKEM",assertions:tests,counts:C,warning:"Exact Shamir access structure and GF(5) histogram only, not QPT or cryptographic-security test. Independently executed local Python has full toy LWE and Ed25519 view."};
}
console.log(JSON.stringify(checker(),null,2));
