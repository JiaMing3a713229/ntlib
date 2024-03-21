# ntlib - CPS-密碼學演算法庫
---
## 下載Library新增至Arduino IDE
#### 至Github下載ntlib Library並添加至Arduino中，步驟如下

#### [Github連結](https://github.com/JiaMing3a713229/ntlib.git)
1. 
![image](https://hackmd.io/_uploads/r1--qQKA6.png)

#### 2. 解壓縮ntlib-main.zip file
![image](https://hackmd.io/_uploads/ry3WomKCT.png)

#### 3. 找到ntlib.zip
![image](https://hackmd.io/_uploads/rJ-Ps7tCa.png)

#### 4. 在Arduino中找到Add ZIP Library選項
![image](https://hackmd.io/_uploads/SyfpsXt0a.png)

#### 5. 選取 ntlib.zip
![image](https://hackmd.io/_uploads/BJTGhQYCa.png)

#### 6. 等待安裝完成，並開啟example進行測試
![image](https://hackmd.io/_uploads/ryi_2mtR6.png)

---
## 測試程式碼:
```c
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

```
---
# **API**
---
## **Init**
#### 此函式用於初始化並配置heap給予RSA演算法相關參數使用，如(e,d,n)，以及定義加密和解密相關函式指標。
```c
rsa_init(&rsa, 29, 31, 113);


@params
struct *rsa  ,引入結構體rsa之位址，為指標變數
uint64_t p   ,RSA 參數 p
uint64_t q   ,RSA 參數 q
uint64_t e   ,RSA 公鑰 e
```

## **Encrypt**
#### 此函式對數值進行加密，message為欲加密訊息之數值
```c
rsa.Encrypt(&rsa, message)
    
@params 
uint64_t message    , 愈加密明文

@return 
uint64_t cipher     , 密文

```

## **Decrypt**
#### 此函式對數值進行解密'，ciphet為欲解密訊息之密文數值
```c
rsa.Decrypt(&rsa, cipher)
    
@params 
uint64_t message    , 愈解密密文

@return 
uint64_t cipher     , 明文

```

---


