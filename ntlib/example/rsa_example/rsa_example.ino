extern "C"{
  #include "ntlib.h"
}

struct RSA rsa;

void setup() {
  
  Serial.begin(115200);
  delay(1000);
  rsa_init(&rsa, 29, 31, 113);  //輸入參數 p = 29; q = 31; e = 113，並生成 d
  delay(5000);
  // Demo
  for(int i = 0; i < 256; ++i){
      uint64_t cipher = rsa.Encrypt(&rsa, i);
      uint64_t plantext = rsa.Decrypt(&rsa, cipher);
      printf("RSA: %10s: %6d , ", "message", i);
      printf(" %10s: %6d ,", "ciphertext", cipher);
      printf("%10s: %6d \r\n", "plantext", plantext);
  }


}

void loop() {
  // put your main code here, to run repeatedly:

}
