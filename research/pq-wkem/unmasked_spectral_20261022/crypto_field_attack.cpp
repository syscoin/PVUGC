// Research-only reproduction of a connected, false, projectively safe SOURCE.
// Source: u^2=z0^2; u*z0=z0^2; xi^2=u*xi;
// (sum xi)*u=(v+1)*u^2, where v=gates-3. All xi enter the target.
// Independent uniform field matrices sampled using
// deterministic test coins. The attack function receives PUBLIC matrices only.
#include <gmpxx.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif
#include <openssl/evp.h>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
using Z=mpz_class;
Z P;
Z mod(const Z& a){Z r;mpz_mod(r.get_mpz_t(),a.get_mpz_t(),P.get_mpz_t());return r;}
Z inverse(const Z& a){Z r;if(!mpz_invert(r.get_mpz_t(),a.get_mpz_t(),P.get_mpz_t()))throw std::runtime_error("noninvertible field value");return r;}
struct Mat {int n,m;std::vector<Z> v;Mat(int n_,int m_):n(n_),m(m_),v((size_t)n_*m_){} Z& at(int i,int j){return v[(size_t)i*m+j];}const Z& at(int i,int j)const{return v[(size_t)i*m+j];}};
Mat mul(const Mat&A,const Mat&B){if(A.m!=B.n)throw std::runtime_error("dimension mismatch");Mat BT(B.m,B.n),C(A.n,B.m);for(int i=0;i<B.n;i++)for(int j=0;j<B.m;j++)BT.at(j,i)=B.at(i,j);for(int i=0;i<A.n;i++)for(int j=0;j<B.m;j++){Z s=0;for(int k=0;k<A.m;k++)mpz_addmul(s.get_mpz_t(),A.at(i,k).get_mpz_t(),BT.at(j,k).get_mpz_t());C.at(i,j)=mod(s);}return C;}
Mat sub(const Mat&A,const Mat&B){Mat C(A.n,A.m);for(size_t i=0;i<A.v.size();i++)C.v[i]=mod(A.v[i]-B.v[i]);return C;}
Mat comm(const Mat&A,const Mat&B){return sub(mul(A,B),mul(B,A));}
Mat inv(Mat A){if(A.n!=A.m)throw std::runtime_error("not square");int n=A.n;Mat B(n,n);for(int i=0;i<n;i++)B.at(i,i)=1;for(int k=0;k<n;k++){int piv=k;while(piv<n && A.at(piv,k)==0)piv++;if(piv==n)throw std::runtime_error("public matrix singular");if(piv!=k)for(int j=0;j<n;j++){std::swap(A.at(piv,j),A.at(k,j));std::swap(B.at(piv,j),B.at(k,j));}Z z=inverse(A.at(k,k));for(int j=k;j<n;j++)A.at(k,j)=mod(A.at(k,j)*z);for(int j=0;j<n;j++)B.at(k,j)=mod(B.at(k,j)*z);for(int i=0;i<n;i++)if(i!=k && A.at(i,k)!=0){Z a=A.at(i,k);A.at(i,k)=0;for(int j=k+1;j<n;j++)A.at(i,j)=mod(A.at(i,j)-a*A.at(k,j));for(int j=0;j<n;j++)B.at(i,j)=mod(B.at(i,j)-a*B.at(k,j));}}return B;}
int rank(Mat A){int r=0;for(int j=0;j<A.m && r<A.n;j++){int piv=r;while(piv<A.n && A.at(piv,j)==0)piv++;if(piv==A.n)continue;if(piv!=r)for(int k=j;k<A.m;k++)std::swap(A.at(piv,k),A.at(r,k));Z z=inverse(A.at(r,j));for(int k=j;k<A.m;k++)A.at(r,k)=mod(A.at(r,k)*z);for(int i=r+1;i<A.n;i++){Z a=A.at(i,j);A.at(i,j)=0;for(int k=j+1;k<A.m;k++)A.at(i,k)=mod(A.at(i,k)-a*A.at(r,k));}r++;}return r;}
Z sample(std::mt19937_64& rng){unsigned bits=mpz_sizeinbase(P.get_mpz_t(),2);Z z;do{z=0;for(unsigned i=0;i<(bits+63)/64;i++){z<<=64;z+=rng();}mpz_fdiv_r_2exp(z.get_mpz_t(),z.get_mpz_t(),bits);}while(z>=P);return z;}
std::string hexhash(const std::string&s){unsigned char out[64];unsigned len=0;EVP_MD_CTX*c=EVP_MD_CTX_new();if(!c)throw std::runtime_error("digest allocation");EVP_DigestInit_ex(c,EVP_sha3_512(),nullptr);EVP_DigestUpdate(c,s.data(),s.size());EVP_DigestFinal_ex(c,out,&len);EVP_MD_CTX_free(c);std::ostringstream o;for(unsigned i=0;i<len;i++)o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)out[i];return o.str();}
std::vector<Mat> setup(int gates,int b,uint64_t seed,const Z&K){std::mt19937_64 rng(seed);int N=2*b*gates+1;Mat L(N,4*b*gates),R(4*b*gates,N);for(auto&z:L.v)z=sample(rng);for(auto&z:R.v)z=sample(rng);Mat U(N,N-1);for(int g=0;g<gates;g++)for(int a=0;a<2*b;a++)for(int i=0;i<N;i++)U.at(i,2*b*g+a)=L.at(i,4*b*g+a);std::vector<Mat>C;std::vector<int>js={0,3,4,5};for(int j:js){Mat W(N-1,N);for(int g=0;g<gates;g++){Mat X(b,b);for(auto&z:X.v)z=sample(rng);for(int half=0;half<2;half++)for(int a=0;a<b;a++)for(int col=0;col<N;col++){Z sum=0;for(int t=0;t<b;t++)mpz_addmul(sum.get_mpz_t(),X.at(a,t).get_mpz_t(),R.at(4*b*g+(2+half)*b+t,col).get_mpz_t());W.at(2*b*g+half*b+a,col)=mod(half==0?-sum:sum);}}Mat M=mul(U,W);
 for(int g=0;g<gates;g++){int a,bb,c,d;if(g==0){a=bb=(j==1);c=d=(j==0);}else if(g==1){a=(j==1);bb=c=d=(j==0);}else if(g<gates-1){a=bb=d=(j==g);c=(j==1);}else{a=(j>=2);bb=d=(j==1);c=(gates-2)*(j==1);}int entries[8][3]={{0,0,a},{0,1,c},{1,0,d},{1,1,bb},{2,2,bb},{2,3,c},{3,2,d},{3,3,a}};for(auto&e:entries)if(e[2])for(int t=0;t<b;t++)for(int row=0;row<N;row++)for(int col=0;col<N;col++)M.at(row,col)=mod(M.at(row,col)+e[2]*L.at(row,4*b*g+e[0]*b+t)*R.at(4*b*g+e[1]*b+t,col));}
 if(j==0)for(int i=0;i<N;i++)M.at(i,i)=mod(M.at(i,i)+K);C.push_back(std::move(M));}return C;}
std::vector<Z> bm(const std::vector<Z>&s){std::vector<Z>C(1,Z(1)),B(1,Z(1));int L=0,shift=1;Z last=1;for(int n=0;n<(int)s.size();n++){Z d=s[n];for(int i=1;i<=L;i++)d+=C[i]*s[n-i];d=mod(d);if(d==0){shift++;continue;}auto T=C;Z a=mod(d*inverse(last));if(C.size()<B.size()+shift)C.resize(B.size()+shift);for(int j=0;j<(int)B.size();j++)C[j+shift]=mod(C[j+shift]-a*B[j]);if(2*L<=n){L=n+1-L;B=T;last=d;shift=1;}else shift++;}C.resize(L+1);std::reverse(C.begin(),C.end());return C;}
std::vector<Z> minpoly(const Mat&A,uint64_t seed){std::mt19937_64 rng(seed);int N=A.n;std::vector<Z>u(N),v(N),s;for(auto&z:u)z=sample(rng);for(auto&z:v)z=sample(rng);s.reserve(2*N);for(int k=0;k<2*N;k++){Z t=0;for(int i=0;i<N;i++)mpz_addmul(t.get_mpz_t(),u[i].get_mpz_t(),v[i].get_mpz_t());s.push_back(mod(t));if(k+1<2*N){std::vector<Z>w(N);for(int i=0;i<N;i++){Z sum=0;for(int j=0;j<N;j++)mpz_addmul(sum.get_mpz_t(),A.at(i,j).get_mpz_t(),v[j].get_mpz_t());w[i]=mod(sum);}v=std::move(w);}}return bm(s);}
struct Attack {Mat A;Mat F0;Mat F1;std::vector<Z>poly;std::vector<Z>hpoly;Attack(Mat a,Mat f0,Mat f1,std::vector<Z>p,std::vector<Z>h):A(std::move(a)),F0(std::move(f0)),F1(std::move(f1)),poly(std::move(p)),hpoly(std::move(h)){} };
Attack attack(std::vector<Mat>C,int b){Mat Q=inv(C[1]);std::cerr<<"reference inverse complete\n";Mat T0=mul(Q,C[0]);Mat TA=mul(Q,C[2]);Mat F0(C[0].n,C[0].n),F1(C[0].n,C[0].n);std::vector<Z>hp;if(b==1){F0=comm(T0,TA);F1=comm(Q,TA);hp=minpoly(TA,919);}else if(b==2){Mat TB=mul(Q,C[3]);Mat S=comm(TA,TB);Mat H=mul(S,S);std::cerr<<"central polynomial complete\n";F0=comm(H,T0);F1=comm(H,Q);std::cerr<<"pencil complete\n";if(C[0].n<=200)hp=minpoly(H,919);else hp={Z(1)};std::cerr<<"structural check finished (omitted above N=200)\n";}else throw std::runtime_error("unsupported block size");C.clear();C.shrink_to_fit();Q.v.clear();Q.v.shrink_to_fit();T0.v.clear();T0.v.shrink_to_fit();TA.v.clear();TA.v.shrink_to_fit();
#ifdef __GLIBC__
malloc_trim(0);
#endif
Mat A=mul(inv(F1),F0);std::cerr<<"attack matrix complete\n";auto p=minpoly(A,20261022);return Attack(std::move(A),std::move(F0),std::move(F1),std::move(p),std::move(hp));}
void array(std::ostream&o,const std::vector<Z>&p){o<<"[";for(size_t i=0;i<p.size();i++){if(i)o<<",";o<<"\""<<p[i].get_str()<<"\"";}o<<"]";}
int main(int argc,char**argv){try{int m=argc>1?std::stoi(argv[1]):96,b=argc>2?std::stoi(argv[2]):2;uint64_t seed=argc>3?std::stoull(argv[3]):5;std::string prefix=argc>4?argv[4]:"crypto_result";P=(Z(1)<<256)+297;if(!mpz_probab_prime_p(P.get_mpz_t(),40))throw std::runtime_error("field failed primality test");std::mt19937_64 keyrng(seed^0x123456789abcdefULL);Z K=sample(keyrng);int N=2*b*m+1;auto start=std::chrono::steady_clock::now();auto C=setup(m,b,seed,K);std::cerr<<"setup complete N="<<N<<"\n";auto a=attack(std::move(C),b);std::cerr<<"public attack complete polynomial degree="<<a.poly.size()-1<<"\n";Mat diff=a.F0;for(size_t i=0;i<diff.v.size();i++)diff.v[i]=mod(diff.v[i]-K*a.F1.v[i]);int rk=rank(diff);Z ev=0;for(auto it=a.poly.rbegin();it!=a.poly.rend();++it)ev=mod(ev*K+*it);if(ev!=0)throw std::runtime_error("test key absent from recovered polynomial");double secs=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();std::ofstream o(prefix+".json");o<<"{\"q\":\""<<P.get_str()<<"\",\"gates\":"<<m<<",\"block\":"<<b<<",\"N\":"<<N<<",\"padding\":1,\"seed\":"<<seed<<",\"rank_at_hidden_key\":"<<rk<<",\"public_key_tag_sha3_512\":\""<<hexhash("unmasked-spectral-test:"+K.get_str())<<"\",\"polynomial_low_to_high\":";array(o,a.poly);o<<",\"structural_matrix_minpoly_low_to_high\":";array(o,a.hpoly);o<<",\"execution_seconds\":"<<secs<<"}\n";std::ofstream r(prefix+"_reference.json");r<<"{\"reference_key_for_validation_only\":\""<<K.get_str()<<"\"}\n";std::cout<<"N="<<N<<" b="<<b<<" rank_at_K="<<rk<<" recovered_polynomial_degree="<<a.poly.size()-1<<" seconds="<<secs<<"\n";}catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}}
