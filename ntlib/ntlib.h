#ifndef _NTLIB_H_
#define _NTLIB_H_
#include<stdint.h>
extern struct _RSA rsa;

struct _RSA{

    struct RSA_Params{
        uint64_t p, q, n, e, d, lambda_n;
    }params;

    uint64_t (*Encrypt)(struct _RSA *rsa, uint32_t message);
    uint64_t (*Decrypt)(struct _RSA *rsa, uint64_t cipher);
};

struct Elgamal{

    struct Elgamal_Params{
        uint64_t p, g;
    }params;

    uint64_t *(*Encrypt)(struct Elgamal *base, uint32_t message, uint64_t Y, uint64_t x);
    uint64_t (*Decrypt)(struct Elgamal *base, uint64_t cipher, uint64_t K);
    uint64_t (*gen_Y)(struct Elgamal *base, uint64_t y);
};

int rsa_init(struct _RSA *rsa, uint64_t p, uint64_t q, uint64_t e);
int Elgamal_init(struct Elgamal *base, uint64_t p, uint64_t g);
// int test(void);




#endif