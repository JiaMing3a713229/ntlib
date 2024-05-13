#ifndef _NTLIB_H_
#define _NTLIB_H_
#include<stdint.h>
extern struct RSA rsa;
struct RSA{

    struct Params{
        uint64_t p, q, n, e, d, lambda_n;
    }params;

    uint64_t (*Encrypt)(struct RSA *rsa, uint32_t message);
    uint64_t (*Decrypt)(struct RSA *rsa, uint64_t cipher);
};

struct Elgamal{
    struct Params_elgamal{
        uint64_t p, g;
    }params;

    uint64_t *(*Encrypt)(struct Elgamal *base, uint32_t message, uint64_t Y, uint64_t x);
    uint64_t (*Decrypt)(struct Elgamal *base, uint64_t cipher, uint64_t K);
    uint64_t (*gen_Y)(struct Elgamal *base, uint64_t y);
};

struct Paillier{
    struct Params_paillier{
        uint64_t p, q, n, n_sqrt, r, g, lambda_n; 
        uint64_t k_p, k_q, h_p, h_q;
    }params;

    uint64_t (*Encrypt)(struct Paillier *paillier, uint32_t message);
    int (*Decrypt)(struct Paillier *paillier, uint64_t cipher);

};

int rsa_init(struct RSA *rsa, uint64_t p, uint64_t q, uint64_t e);
uint64_t  Elgamal_init(struct Elgamal *base, uint64_t p, uint64_t g);
uint64_t Paillier_init(struct Paillier *paillier, uint64_t p, uint64_t q, uint64_t r, uint64_t g);
int test(void);

#endif