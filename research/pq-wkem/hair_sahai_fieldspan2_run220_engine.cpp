#include <bits/stdc++.h>
using namespace std; using u16=uint16_t; using u32=uint32_t; using u64=uint64_t;
static u32 B[16][4]; struct Mat{u32 c[4];}; static Mat W[65536];
static int rank24_early(const u32* vs,int n,int stop=25){u32 bas[24]{};int r=0;for(int k=0;k<n;k++){u32 v=vs[k];for(int p=23;p>=0;p--)if((v>>p)&1U){if(bas[p])v^=bas[p];else{bas[p]=v;if(++r>=stop)return r;break;}}}return r;}
static uint8_t mul16(uint8_t a,uint8_t b){uint8_t z=0;while(b){if(b&1)z^=a;b>>=1;a<<=1;if(a&0x10)a^=0x13;}return z&15;}
static uint8_t inv16(uint8_t a){for(int b=1;b<16;b++)if(mul16(a,b)==1)return b;return 0;}
static u16 scal(u16 g,uint8_t l){u16 o=0;for(int i=0;i<4;i++)o|=u16(mul16((g>>(4*i))&15,l))<<(4*i);return o;}
static int canon16(const u16* vs,int n,u16*out){u16 bas[16]{};int r=0;for(int k=0;k<n;k++){u16 v=vs[k];for(int p=15;p>=0;p--)if((v>>p)&1U){if(bas[p])v^=bas[p];else{bas[p]=v;r++;break;}}}for(int p=15;p>=0;p--)if(bas[p])for(int q=15;q>=0;q--)if(q!=p&&bas[q]&&((bas[q]>>p)&1U))bas[q]^=bas[p];int z=0;for(int p=15;p>=0;p--)if(bas[p])out[z++]=bas[p];return r;}
static int canon8(const uint8_t*vs,int n,uint8_t*out){uint8_t bas[8]{};int r=0;for(int k=0;k<n;k++){uint8_t v=vs[k];for(int p=7;p>=0;p--)if((v>>p)&1){if(bas[p])v^=bas[p];else{bas[p]=v;r++;break;}}}for(int p=7;p>=0;p--)if(bas[p])for(int q=7;q>=0;q--)if(q!=p&&bas[q]&&((bas[q]>>p)&1))bas[q]^=bas[p];int z=0;for(int p=7;p>=0;p--)if(bas[p])out[z++]=bas[p];return r;}
static u32 pack3(const uint8_t*b){return u32(b[0])|(u32(b[1])<<8)|(u32(b[2])<<16);} 
static vector<array<uint8_t,5>> all5(){unordered_set<u32> seen;seen.reserve(120000);for(int a=1;a<256;a++)for(int b=a+1;b<256;b++)for(int c=b+1;c<256;c++){uint8_t in[3]={(uint8_t)a,(uint8_t)b,(uint8_t)c}, rr[3]{};if(canon8(in,3,rr)!=3)continue;seen.insert(pack3(rr));}vector<array<uint8_t,5>> out;out.reserve(seen.size());for(u32 pk:seen){uint8_t h[3]={(uint8_t)pk,(uint8_t)(pk>>8),(uint8_t)(pk>>16)}; // orthogonal complement in F2^8
 vector<uint8_t> sol; for(int x=1;x<256;x++){bool ok=true;for(int i=0;i<3;i++)if(__builtin_parity((unsigned)x & h[i])){ok=false;break;}if(ok)sol.push_back((uint8_t)x);} uint8_t bas[8]{}; int r=canon8(sol.data(),(int)sol.size(),bas); if(r!=5){cerr<<"bad complement\n";exit(2);} array<uint8_t,5>A{};for(int i=0;i<5;i++)A[i]=bas[i];out.push_back(A);} sort(out.begin(),out.end());return out;}
static u64 plane_key(u16 a,u16 b){uint8_t A[2][4]{};for(int j=0;j<4;j++){A[0][j]=(a>>(4*j))&15;A[1][j]=(b>>(4*j))&15;}int r=0;for(int c=0;c<4&&r<2;c++){int p=-1;for(int i=r;i<2;i++)if(A[i][c]){p=i;break;}if(p<0)continue;if(p!=r)for(int j=0;j<4;j++)swap(A[p][j],A[r][j]);uint8_t iv=inv16(A[r][c]);for(int j=0;j<4;j++)A[r][j]=mul16(A[r][j],iv);for(int i=0;i<2;i++)if(i!=r&&A[i][c]){uint8_t f=A[i][c];for(int j=0;j<4;j++)A[i][j]^=mul16(f,A[r][j]);}r++;}if(r!=2)return ULLONG_MAX;u16 x=0,y=0;for(int j=0;j<4;j++){x|=u16(A[0][j])<<(4*j);y|=u16(A[1][j])<<(4*j);}return u64(x)|(u64(y)<<16);}
int main(){for(int i=0;i<16;i++)for(int c=0;c<4;c++){u64 x;if(!(cin>>x))return 3;B[i][c]=x;}for(int g=0;g<65536;g++)for(int c=0;c<4;c++){u32 x=0;for(int i=0;i<16;i++)if((g>>i)&1)x^=B[i][c];W[g].c[c]=x;}
 // projective lines reps
 vector<u16> lines; unordered_set<u16> ls; for(int g=1;g<65536;g++){u16 gg=g;u16 rep=0;for(int i=0;i<4;i++){uint8_t a=(gg>>(4*i))&15;if(a){rep=scal(gg,inv16(a));break;}}ls.insert(rep);} lines.assign(ls.begin(),ls.end());sort(lines.begin(),lines.end());
 unordered_set<u64> planes;planes.reserve(80000);for(size_t i=0;i<lines.size();i++)for(size_t j=i+1;j<lines.size();j++)planes.insert(plane_key(lines[i],lines[j]));cerr<<"planes "<<planes.size()<<"\n";
 map<int,u64> planeHist; vector<pair<u16,u16>> special; for(u64 K:planes){u16 a=K&0xffff,b=(K>>16)&0xffff;u16 bb[8]={scal(a,1),scal(a,2),scal(a,4),scal(a,8),scal(b,1),scal(b,2),scal(b,4),scal(b,8)};u16 cb[8]{};if(canon16(bb,8,cb)!=8){cerr<<"bad8\n";return 2;}u32 vv[32];int n=0;for(int i=0;i<8;i++)for(int c=0;c<4;c++)vv[n++]=W[cb[i]].c[c];int sp=rank24_early(vv,32,25); ++planeHist[sp]; if(sp==20)special.push_back({a,b});}
 cerr<<"special "<<special.size()<<"\n"; auto subs=all5();cerr<<"sub5 "<<subs.size()<<"\n";
 map<int,u64> hist; int globalMin=99; u64 checked=0; u16 bestBasis[5]{}; pair<u16,u16> bestPlane{};
 for(auto [a,b]:special){u16 coord[8]={scal(a,1),scal(a,2),scal(a,4),scal(a,8),scal(b,1),scal(b,2),scal(b,4),scal(b,8)};u16 word[256]{};for(int x=0;x<256;x++){u16 g=0;for(int i=0;i<8;i++)if((x>>i)&1)g^=coord[i];word[x]=g;}
   for(auto &sb:subs){u32 bas[24]{};int r=0; for(int bi=0;bi<5;bi++){u16 g=word[sb[bi]];for(int c=0;c<4;c++){u32 v=W[g].c[c];for(int p=23;p>=0;p--)if((v>>p)&1U){if(bas[p])v^=bas[p];else{bas[p]=v;r++;break;}}}}
     int sp=r;
     if(sp<globalMin){globalMin=sp;bestPlane={a,b};for(int i=0;i<5;i++)bestBasis[i]=word[sb[i]];}
     hist[sp]++; checked++;
   }
 }
 cout<<"{\"field_planes_total\":"<<planes.size()<<",\"field_plane_support_histogram\":{";bool fpfirst=true;for(auto &kv:planeHist){if(!fpfirst)cout<<",";fpfirst=false;cout<<"\""<<kv.first<<"\":"<<kv.second;}cout<<"},\"support20_planes\":"<<special.size()<<",\"binary_5_subspaces_per_plane\":"<<subs.size()<<",\"support20_binary_5_checked\":"<<checked<<",\"support20_min_exact_support\":"<<globalMin<<",\"support20_le11_count\":";u64 le11=0;for(auto &kv:hist)if(kv.first<=11)le11+=kv.second;cout<<le11<<",\"support20_subspace_histogram\":{";bool first=true;for(auto &kv:hist){if(!first)cout<<",";first=false;cout<<"\""<<kv.first<<"\":"<<kv.second;}cout<<"},\"support13_example_plane\":["<<bestPlane.first<<","<<bestPlane.second<<"],\"support13_example_basis\":[";for(int i=0;i<5;i++){if(i)cout<<",";cout<<bestBasis[i];}cout<<"]}\n";
}
