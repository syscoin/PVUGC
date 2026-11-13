const check = function check(){
let count=0;function ok(x){if(!x)throw Error("certificate/test failed at "+count);count++;}
const pairs=[];for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)pairs.push([i,j]);
let bads=Array(6).fill(0);
for(let ecode=0;ecode<625;ecode++){let v=ecode,e=[];for(let i=0;i<4;i++){e.push(v%5-2);v=Math.floor(v/5)}for(let j=0;j<6;j++){let[a,b]=pairs[j];if(Math.abs(e[a]+e[b])>=2)bads[j]++}}
ok(bads.every(x=>x===300));
let badTotal=0,badWitnesses=0,sourceTrue=0,joints=Array(6).fill(0);
for(let bcode=0;bcode<256;bcode++){let v=bcode,B=[];for(let i=0;i<4;i++){B.push(v%4);v=Math.floor(v/4)}let mask=pairs.map(([a,b])=>(B[a]+B[b])%4===0);if(mask.some(Boolean))sourceTrue++;
for(let ecode=0;ecode<625;ecode++){let u=ecode,e=[];for(let i=0;i<4;i++){e.push(u%5-2);u=Math.floor(u/5)}let any=false;for(let j=0;j<6;j++){let[a,b]=pairs[j];if(mask[j]&&Math.abs(e[a]+e[b])>=2){any=true;badWitnesses++;joints[j]++}}if(any)badTotal++}}
for(let j=0;j<6;j++)ok(joints[j]*4===bads[j]*256);
ok(badWitnesses===115200);ok(badTotal===86264);ok(sourceTrue===214);ok(badTotal<=badWitnesses);
const B=[0,0,1,15],valid=[[0,1],[2,3]];let recovered=0;for(let t=0;t<16;t++)for(let u=0;u<16;u++)for(let ecode=0;ecode<81;ecode++){let z=ecode,e=[];for(let i=0;i<4;i++){e.push(z%3-1);z=Math.floor(z/3)}let p=B.map((v,i)=>((2*t+v*u+e[i])%16+16)%16);for(const[a,b]of valid){let E=e[a]+e[b];if(Math.abs(E)<2){let y=(p[a]+p[b])%16;ok(y===(4*t+E+16)%16);ok((Math.floor((y+2)/4)%4)===(t%4));recovered++}}}
ok(recovered===32256);
const comb=(n,k)=>{let z=1n;for(let i=1n;i<=BigInt(k);i++)z=z*(BigInt(n)-i+1n)/i;return z};
const M=comb(4096,128);ok(M>(1n<<816n)&&M<(1n<<817n));ok((1n<<640n)*(1n<<176n)<M);
const gg=2048,H=128,ell=29,dim=4096,a=20;ok(gg%H===0);ok((gg/H)*dim<2**a);ok(gg*gg*25===400*8*H*256);ok(Math.ceil(256/(a-11))===ell);
ok((2n*29n*M*(1n<<217n))<(1n<<1040n));
const couplingNumerator=BigInt(dim*ell)*((1n<<(313n-157n))+1n);
ok(couplingNumerator*(1n<<139n)<(1n<<313n));
const scale=400n,numerator=(1n<<(scale-217n))+(1n<<(scale-139n));ok(numerator*(1n<<137n)<(1n<<scale)-(1n<<(scale-176n)));
return {record:"random-kernel-filtered-gaussian-20261027-turn11",status:"PASS",assertions:count,toy:{matrices:256,error_vectors:625,source_true_matrices:sourceTrue,bad_joint_events:badTotal,bad_witness_events:badWitnesses,two_valid_witness_good_openings:recovered},certificate:{g:2048,ell:29,previous_ell:32,source_false:"<2^-176",all_witness_failure:"<2^-138",conditional_on_true_failure:"<2^-137",qpt_hardness_certified:false}};
};
console.log(JSON.stringify(check()));
