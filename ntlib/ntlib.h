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

struct Elgamel{
    struct Params{
        uint64_t p, g;
    }params;

    uint64_t (*Encrypt)(struct Elgamel *base, uint32_t message);
    uint64_t (*Decrypt)(struct Elgamel *base, uint64_t cipher);
    uint64_t (*gen_Y)(struct Elgamel *base, uint64_t y);
};

int rsa_init(struct RSA *rsa, uint64_t p, uint64_t q, uint64_t e);
uint64_t  Elgamel_init(struct Elgamel *base, uint64_t p, uint64_t g);
int test(void);




#endif