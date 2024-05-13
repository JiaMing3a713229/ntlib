#include "ntlib.h"
#include <stdio.h>

#define MODE 1

static uint64_t gcdof(uint64_t a, uint64_t b)
{   
    /* swap the value of a and b */
    if(a > b){   
        a ^= b;
        b ^= a;
        a ^= b;
    }
    return (a == 0)? b : gcdof(b % a, a);
}

static uint64_t powof(uint64_t b, uint64_t pow, uint64_t mod_size)
{   

    uint64_t ret = 1;
    while(pow != 0){
        if((pow & 1) == 1){
            ret = (ret * b) % mod_size;  
        }
        pow >>= 1;
        b = (b * b) % mod_size;
    }
    return ret % mod_size;
}

static inline uint64_t lcmof(uint64_t a, uint64_t b)
{
    return (a * b) / gcdof(a, b);
}

static uint64_t exgcd(uint32_t mod_size, uint32_t r, uint32_t d1, uint32_t d2)
{
    int q = mod_size / r;
    return (r == 1)? d2 : exgcd(r, (mod_size % r), d2, (d1 - q * d2));
}

static inline uint64_t invof(uint64_t num, uint64_t mod_size)
{   
    int ret = 0;
    if(gcdof(num, mod_size) == 1){
        ret = (gcdof(num, mod_size) == 1) ? exgcd(mod_size, num, 0, 1) : 0;
    }
    return (ret < 0)? (ret+ mod_size): ret;
    
}

static inline uint64_t Encrypt_RSA(struct RSA *rsa, uint32_t message)
{
    return powof(message, rsa->params.e, rsa->params.n);                              // m^e (mod n)
}

// RSA Decryption:D(c)=m = c^d mod n
static inline uint64_t Decrypt_RSA(struct RSA *rsa, uint64_t cipher)
{
    return powof(cipher, rsa->params.d, rsa->params.n);
}

int rsa_init(struct RSA *rsa, uint64_t p, uint64_t q, uint64_t e)
{   
    rsa->Encrypt = Encrypt_RSA;
    rsa->Decrypt = Decrypt_RSA;

    rsa->params.p = p;
    rsa->params.q = q;
    rsa->params.n = (rsa->params.p) * (rsa->params.q);

    
    rsa->params.lambda_n = lcmof((rsa->params.p -1) , (rsa->params.q -1));
    rsa->params.e = e;
    rsa->params.d = invof((rsa->params.e), (rsa->params.lambda_n));    
    printf("------------key--gen--------------\r\n");
    printf("RSA: %5s: %8llu \r\n", "p", rsa->params.p);
    printf("RSA: %5s: %8llu \r\n", "q", rsa->params.q);
    printf("RSA: %5s: %8llu \r\n", "n", rsa->params.n);
    printf("RSA: %5s: %8llu \r\n", "e", rsa->params.e);
    printf("RSA: %5s: %8llu \r\n", "lambel", rsa->params.lambda_n);
    printf("RSA: %5s: %8llu \r\n", "d", rsa->params.d);
    printf("------------key--gen-seccess------\r\n");

    
}

static inline uint64_t* Encrypt_Elgamal(struct Elgamal *base, uint32_t message, uint64_t Y, uint64_t x)
{
    uint64_t *ret = (uint64_t*)malloc(sizeof(uint64_t) * 2);  //需要free(ret)
    uint64_t K = powof(Y, x, base->params.p);
    uint64_t c = (K * message) % (base->params.p);
    ret[0] = K;
    ret[1] = c;
    return ret;  //return (K,c),{k, c}
}

// RSA Decryption:D(c)=m = c^d mod n
static inline uint64_t Decrypt_Elgamal(struct Elgamal *base, uint64_t cipher, uint64_t K)
{
    return (cipher * invof(K, base->params.p)) % base->params.p;
}

static inline uint64_t gen_Y(struct Elgamal *base, uint64_t y)
{
    return powof(base->params.g, y, base->params.p);
}

uint64_t Elgamal_init(struct Elgamal *base, uint64_t p, uint64_t g)
{
    
    base->params.p = p;
    base->params.g = g;
    
    printf("------------key--gen--------------\r\n");
    printf("Elgamal: %5s: %8llu \r\n", "p", base->params.p);
    printf("Elgamal: %5s: %8llu \r\n", "g", base->params.g);
    printf("----------key--gen-seccess--------\r\n");
    base->Encrypt = Encrypt_Elgamal;
    base->Decrypt = Decrypt_Elgamal;
    base->gen_Y = gen_Y;
    
}

static inline uint64_t L_func(uint64_t u, uint64_t den)
{
    return (u - 1)/(den);
}

static inline int CRT(struct Paillier *paillier, uint64_t mp, uint64_t mq)
{
    uint64_t M = paillier->params.n;
    uint64_t M1 = paillier->params.q;
    uint64_t M1_inv = invof(M1, paillier->params.p);
    uint64_t M2 = paillier->params.p;
    uint64_t M2_inv = invof(M2, paillier->params.q);
    
    return ((mp*M1*M1_inv) + (mq*M2*M2_inv)) % M;
    
}

static inline uint64_t Encrypt_Paillier(struct Paillier *paillier, uint32_t message)
{
    uint64_t c = powof(paillier->params.g, message, paillier->params.n_sqrt) * powof(paillier->params.r, paillier->params.n, paillier->params.n_sqrt);
    return c % (paillier->params.n_sqrt);
}

static inline int Decrypt_Paillier(struct Paillier *paillier, uint64_t cipher)
{
    int ret = 0;
    #if (MODE == 0)
    uint64_t m1 = L_func(powof(cipher, paillier->params.lambda_n, paillier->params.n_sqrt), paillier->params.n);
    uint64_t m2 = L_func(powof(paillier->params.g, paillier->params.lambda_n, paillier->params.n_sqrt), paillier->params.n);
    uint64_t u = invof(m2, paillier->params.n);
    ret = (m1*u) % paillier->params.n;
    #elif (MODE == 1)
    uint64_t u_1 = powof(cipher, ((paillier->params.p) - 1), (paillier->params.p)*(paillier->params.p));
    uint64_t m_p = (L_func(u_1, paillier->params.p) * (paillier->params.h_p)) % (paillier->params.p);

    uint64_t u_2 = powof(cipher, ((paillier->params.q) - 1), (paillier->params.q)*(paillier->params.q));
    uint64_t m_q = (L_func(u_2, paillier->params.q) * (paillier->params.h_q)) % (paillier->params.q);

    ret = CRT(paillier, m_p, m_q);
    #endif

    return ret;
}

uint64_t Paillier_init(struct Paillier *paillier, uint64_t p, uint64_t q, uint64_t r, uint64_t g)
{
    paillier->params.p = p;
    paillier->params.q = q;
    paillier->params.r = r;
    paillier->params.g = g;
    paillier->params.n = p * q;
    paillier->params.n_sqrt = (paillier->params.n) * (paillier->params.n);
    paillier->params.lambda_n = lcmof((p -1) , (q -1));

    
    // For CRT
    paillier->params.k_p = L_func(powof(paillier->params.g, (p-1), (p*p)), p);
    paillier->params.k_q = L_func(powof(paillier->params.g, (q-1), (q*q)), q);
    paillier->params.h_p = invof(paillier->params.k_p, p);
    paillier->params.h_q = invof(paillier->params.k_q, q);

    printf("------------key--gen--------------\r\n");
    printf("Paillier: %5s: %8llu \r\n", "p", paillier->params.p);
    printf("Paillier: %5s: %8llu \r\n", "q", paillier->params.q);
    printf("Paillier: %5s: %8llu \r\n", "r", paillier->params.r);
    printf("Paillier: %5s: %8llu \r\n", "g", paillier->params.g);
    printf("Paillier: %5s: %8llu \r\n", "n", paillier->params.n);
    printf("Paillier: %5s: %8llu \r\n", "n^2", paillier->params.n_sqrt);
    printf("Paillier: %5s: %8llu \r\n", "lambda(n)", paillier->params.lambda_n);
    printf("----------key--gen-seccess--------\r\n");

    paillier->Encrypt = Encrypt_Paillier;
    paillier->Decrypt = Decrypt_Paillier;

}

int test(void)
{
    printf("%llu \r\n", powof(5588, 4879, 282943));
}
