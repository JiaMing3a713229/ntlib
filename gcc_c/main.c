#include "..\ntlib\ntlib.h"
#include <stdio.h>


struct _RSA rsa;
int main(void){

    rsa_init(&rsa, 523, 541, 199);  //輸入參數 p = 29; q = 31; e = 113，並生成 d
  
    // Demo
    for(int i = 0; i < 256; ++i){
        uint64_t cipher = rsa.Encrypt(&rsa, i);
        uint64_t plantext = rsa.Decrypt(&rsa, cipher);
        printf("RSA: %10s: %d , ", "message", i);
        printf(" %10s: %6lu ,", "ciphertext", cipher);
        printf("%10s: %6lu \r\n", "plantext",plantext);
    }

    return 0;
}