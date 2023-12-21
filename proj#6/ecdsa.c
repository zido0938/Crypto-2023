        /*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */

#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include "ecdsa.h"
#include "sha2.h"
#include <gmp.h>
#include <string.h>

mpz_t p, n;
ecdsa_p256_t G;

// sha() - 사용할 sha 함수를 선택
void sha(const unsigned char *data, unsigned int len, unsigned char *digest, int sha2_ndx)
{
    switch (sha2_ndx){
        case SHA224:
            sha224(data, len, digest);
            break;
        case SHA256:
            sha256(data, len, digest);
            break;
        case SHA384:
            sha384(data, len, digest);
            break;
        case SHA512:
            sha512(data, len, digest);
            break;
        case SHA512_224:
            sha512_224(data, len, digest);
            break;
        case SHA512_256:
            sha512_256(data, len, digest);
            break;
   }
}


// SHA2SIZE() - 사용할 sha2 함수의 길이를 반환
int SHA2SIZE(int sha2_ndx)
{
   switch (sha2_ndx)
   {
      case SHA224:
         return SHA224_DIGEST_SIZE;
      case SHA256:
         return SHA256_DIGEST_SIZE;
      case SHA384:
         return SHA384_DIGEST_SIZE;
      case SHA512:
         return SHA512_DIGEST_SIZE;
      case SHA512_224:
         return SHA224_DIGEST_SIZE;
      case SHA512_256:
         return SHA256_DIGEST_SIZE;
   }
   return 0;
}

// ecc상의 덧셈 계산, P!=Q 인 경우의 계산, 계산 결과 R을 반환해준다
int ecc_add(ecdsa_p256_t *P, ecdsa_p256_t *Q, ecdsa_p256_t *R)
{
    mpz_t x1, y1, x2, y2, x3, y3, tmp;
    mpz_inits(x1, y1, x2, y2, x3, y3, tmp, NULL);
    mpz_import(x1, ECDSA_P256/8, 1, 1, 1, 0, P->x);
    mpz_import(y1, ECDSA_P256/8, 1, 1, 1, 0, P->y);
    mpz_import(x2, ECDSA_P256/8, 1, 1, 1, 0, Q->x);
    mpz_import(y2, ECDSA_P256/8, 1, 1, 1, 0, Q->y);

   if(mpz_cmp_ui(x1,0)==0&&mpz_cmp_ui(y1,0)==0){
      // O + Q = Q
      mpz_set(x3,x2);
      mpz_set(y3,y2);
   }else if(mpz_cmp_ui(x2,0)==0&&mpz_cmp_ui(y2,0)==0){
      // P + O = P
      mpz_set(x3,x1);
      mpz_set(y3,y1);
   }else{
    // x3 생성
    mpz_sub(x3, y2, y1);   // x3 = y2 - y1
    mpz_sub(tmp, x2, x1);  // tmp = x2 - x1

    // P + Q = O일 경우 오류발생
    if(mpz_cmp_ui(tmp, 0) == 0){
      mpz_clears(x1, y1, x2, y2, x3, y3, tmp, NULL);
      return 1;
    }

    mpz_invert(tmp, tmp, p);  // inverse(x2 - x1) (mod n)
    mpz_mul(tmp, x3, tmp);    // tmp = (y2 - y1) / (x2 - x1)
    mpz_mul(x3, tmp, tmp);    // x3 = ((y2 - y1) / (x2 - x1))^2
    mpz_sub(x3, x3, x1);      // x3 = ((y2 - y1) / (x2 - x1))^2 - x1
    mpz_sub(x3, x3, x2);      // x3 = ((y2 - y1) / (x2 - x1))^2 - x1 - x2
    mpz_mod(x3, x3, p);       // x3 mod n

   // y3 생성
    mpz_sub(y3, x1, x3);      // y3 = x1 - x3
    mpz_mul(y3, tmp, y3);     // y3 = ((y2 - y1) / (x2 - x1))(x1 - x3)
    mpz_sub(y3, y3, y1);      // y3 = ((y2 - y1) / (x2 - x1))(x1 - x3) - y1
    mpz_mod(y3, y3, p);       // y3 mod n
   }
  
    mpz_export(R->x, NULL, 1, ECDSA_P256/8, 1, 0, x3);
    mpz_export(R->y, NULL, 1, ECDSA_P256/8, 1, 0, y3);
    mpz_clears(x1, y1, x2, y2, x3, y3, tmp, NULL);
    return 0;
}

// ecc상의 덧셈 계산, P=Q인 경우 즉 2P계산 결과를 R으로 반환해준다
int ecc_doubling(ecdsa_p256_t *P, ecdsa_p256_t *R)
{
    mpz_t x1, y1, x3, y3, tmp;
    mpz_inits(x1, y1, x3, y3, tmp, NULL);
    mpz_import(x1, ECDSA_P256/8, 1, 1, 1, 0, P->x);
    mpz_import(y1, ECDSA_P256/8, 1, 1, 1, 0, P->y);

    // x3 생성
    mpz_mul(x3, x1, x1);      // x3 = x1^2
    mpz_mul_ui(x3, x3, 3);    // x3 = 3x1^2
    mpz_sub_ui(x3, x3, 3);    // x3 = 3x1^2 - 3
    mpz_mul_ui(tmp, y1, 2);   // tmp = 2y1
    mpz_invert(tmp, tmp, p);  // inverse(2y1)(mod n)
    mpz_mul(tmp, x3, tmp);    // tmp = (3x1^2 - 3) / 2y1
    mpz_mul(x3, tmp, tmp);    // x3 = ((3x1^2 - 3) / 2y1)^2
    mpz_sub(x3, x3, x1);      // x3 = ((3x1^2 - 3) / 2y1)^2 - x1
    mpz_sub(x3, x3, x1);      // x3 = ((3x1^2 - 3) / 2y1)^2 - 2x1
    mpz_mod(x3, x3, p);

    // y3 생성
    mpz_sub(y3, x1, x3);      // y3 = x1 - x3
    mpz_mul(y3, tmp, y3);     // y3 = ((3x1^2 - 3) / 2y1)(x1 - x3)
    mpz_sub(y3, y3, y1);      // y3 = ((3x1^2 - 3) / 2y1)(x1 - x3) - y1
    mpz_mod(y3, y3, p);
    
    mpz_export(R->x, NULL, 1, ECDSA_P256/8, 1, 0, x3);
    mpz_export(R->y, NULL, 1, ECDSA_P256/8, 1, 0, y3);
    mpz_clears(x1, y1, x3, y3, tmp, NULL);
    return 0;
}

// ecc상의 곱셈, square multiply 활용하여 A를 d번더하는 계산을 수행한다
void ecc_mul(ecdsa_p256_t *X, mpz_t d, ecdsa_p256_t *Y)
{
    unsigned long int i = 0;
    unsigned long int bin_bits = ECDSA_P256;

    // i = d 이고 i=d이기 전까지 계속 Y에 X를 더해준다
    while(i <= bin_bits){
        if(mpz_tstbit(d, i)==1) ecc_add(Y, X, Y);
        // X+X 즉 X를 두배로만들고 저장(비트를 shift하는 square multiply 방식과 유사)
        ecc_doubling(X, X);
        i++;
   }
}

/*
 * Initialize 256 bit ECDSA parameters
 * 시스템파라미터 p, n, G의 공간을 할당하고 값을 초기화한다.
 */
void ecdsa_p256_init(void)
{
    mpz_t g_x, g_y;
    mpz_inits(g_x, g_y, NULL);

    mpz_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    mpz_set_str(g_x, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    mpz_set_str(g_y, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);

    mpz_export(G.x, NULL, 1, ECDSA_P256/8, 1, 0, g_x);
    mpz_export(G.y, NULL, 1, ECDSA_P256/8, 1, 0, g_y);

    mpz_clears(g_x, g_y, NULL);
}

/*
 * Clear 256 bit ECDSA parameters
 * 할당된 파라미터 공간을 반납한다.
 */
void ecdsa_p256_clear(void)
{
   mpz_clears(p, n, NULL);
}

/*
 * ecdsa_p256_key() - generates Q = dG
 * 사용자의 개인키와 공개키를 무작위로 생성한다.
 */

void ecdsa_p256_key(void *d, ecdsa_p256_t *Q)
{
   mpz_t temp_d;
   mpz_init(temp_d);

   // mpz_urandomm으로 랜덤값 temp_d 생성
   gmp_randstate_t state;
   gmp_randinit_default(state);
   gmp_randseed_ui(state, arc4random());
   mpz_urandomm(temp_d, state, n);

   // Q = d*G
   ecdsa_p256_t temp_G;  // G값을 저장하고 계산에 이용할 임시 변수 temp_G 생성
   memset(Q->x,0,ECDSA_P256/8);        // Q->x 초기화
   memset(Q->y,0,ECDSA_P256/8);        // Q->y 초기화
   memcpy(&temp_G.x,&G.x,ECDSA_P256/8); // G의 x값 복사
   memcpy(&temp_G.y,&G.y,ECDSA_P256/8); // G의 x값 복사
   ecc_mul(&temp_G, temp_d, Q);
   
   mpz_export(d, NULL, 1, ECDSA_P256/8, 1, 0, temp_d);

   mpz_clear(temp_d);
}

/*
 * ecdsa_p256_sign(msg, len, d, r, s) - ECDSA Signature Generation
 * 길이가 len 바이트인 메시지 m을 개인키 d로 서명한 결과를 r, s에 저장한다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. r과 s의 길이는 256비트이어야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_sign(const void *msg, size_t len, const void *d, void *_r, void *_s, int sha2_ndx)
{
   unsigned char e[SHA512_DIGEST_SIZE];
   int h_len;
   mpz_t temp_e, temp_d, k, r, s;
   ecdsa_p256_t signature;
   gmp_randstate_t state;

   // Step1. e = H(m). H()는 SHA-2 해시함수이다.
   sha(msg, len, e, sha2_ndx);
   
   // Step2. e의 길이가 n의 길이(256비트)보다 길면 뒷 부분은 자른다. bitlen(e) ≤ bitlen(n)
   if (sha2_ndx == SHA384 || sha2_ndx == SHA512) h_len = SHA256_DIGEST_SIZE;
   else h_len = SHA2SIZE(sha2_ndx); // 기존 비트 수 유지
   mpz_inits(temp_e, temp_d, k, r, s, NULL);
   mpz_import(temp_e, h_len, 1, 1, 1, 0, e);  // 해시 길이만큼 e를 잘라서 저장
   mpz_import(temp_d, ECDSA_P256 / 8, 1, 1, 1, 0, d);
   
   ecdsa_p256_t temp_G;  // G값을 저장하고 계산에 이용할 임시 변수 temp_G 선언
   gmp_randinit_default(state);
   gmp_randseed_ui(state, arc4random());
   do
   {
      // Step3. 비밀값 k를 무작위로 선택한다. (0 < k < n)
      mpz_urandomm(k, state, n);

      // Step4. (x1, y1) = k*G
      memset(signature.x, 0, ECDSA_P256 / 8);   // x1 초기화
      memset(signature.y, 0, ECDSA_P256 / 8);   // y1 초기화
      memcpy(&temp_G.x,&G.x,ECDSA_P256/8);       // G의 x값 복사
      memcpy(&temp_G.y,&G.y,ECDSA_P256/8);       // G의 y값 복사

      ecc_mul(&temp_G, k, &signature);   // (x1, y1) 생성

      // Step5. r = x1 mod n
      mpz_import(r, ECDSA_P256 / 8, 1, 1, 1, 0, signature.x);
      mpz_mod(r, r, n);

      // Step6. s = k^-1 * (e + rd) mod n
      mpz_invert(k, k, n);    // k = k^-1
      mpz_mul(temp_d, r, temp_d);     // temp_d = r*d
      mpz_add(temp_d, temp_e, temp_d);    // temp_d = e + r*d
      mpz_mul(s, k, temp_d);      // s = k^-1 * (e + rd)
      mpz_mod(s, s, n);       // s = k^-1 * (e + rd) mod n

   } while (mpz_cmp_ui(r, 0) == 0 || mpz_cmp_ui(s, 0) == 0);

   mpz_export(_r, NULL, 1, ECDSA_P256 / 8, 1, 0, r);
   mpz_export(_s, NULL, 1, ECDSA_P256 / 8, 1, 0, s);

   mpz_clears(temp_e, temp_d, k, r, s, NULL);

   return 0;
}

/*
 * ecdsa_p256_verify(msg, len, Q, r, s) - ECDSA signature veryfication
 * It returns 0 if valid, nonzero otherwise.
 * 길이가 len 바이트인 메시지 m에 대한 서명이 (r,s)가 맞는지 공개키 Q로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *_Q, const void *_r, const void *_s, int sha2_ndx)
{
   // m의 길이가 hash function의 최대크기(2^61-1)보다 클 경우 오류 반환
   if (len>0x1fffffffffffffff)
       return ECDSA_MSG_TOO_LONG;
   
   unsigned char e[SHA512_DIGEST_SIZE];
   int h_len;
   mpz_t r, s, temp_e, temp, w, u1, u2, x1, v;
   ecdsa_p256_t u1G, u2Q, XY;

   mpz_inits(r, s, temp_e, w, temp, u1, u2, x1, v, NULL);
   mpz_import(r, ECDSA_P256/8, 1, 1, 1, 0, _r);
   mpz_import(s, ECDSA_P256/8, 1, 1, 1, 0, _s);

   // Step1. r과 s가 [1,n-1] 사이에 있지 않으면 잘못된 서명이다.
   mpz_sub_ui(temp, n, 1);
   if (mpz_cmp_ui(r,1) < 0 || mpz_cmp(r,temp) > 0 || mpz_cmp_ui(s,1) < 0 || mpz_cmp(s,temp) > 0) return ECDSA_SIG_INVALID;

   // Step2. e=H(m) H()는 서명에서 사용한 해시함수와 같다.
   sha(msg, len, e, sha2_ndx);
    
   // Step3. e의 길이가 n의 길이(256비트)보다 길면 뒷 부분을 자른다. bitlen(e) <= bitlen(n)
   if (sha2_ndx == SHA384 || sha2_ndx == SHA512) h_len = SHA256_DIGEST_SIZE;
   else h_len=SHA2SIZE(sha2_ndx);
   mpz_import(temp_e, h_len, 1, 1, 1, 0, e);  // 해시 길이만큼 e를 잘라서 저장

   // Step4. u1 = es^-1 mod n, u2 = rs^-1 mod n
   mpz_invert(w, s, n);  // w = s^-1 mod n
   mpz_mul(u1, temp_e, w);   // u1 = e*s^-1
   mpz_mul(u2, r, w);    // u2 = r*s^-1
   mpz_mod(u1, u1, n);   // u1 = u1 mod n
   mpz_mod(u2, u2, n);   // u2 = u2 mod n

   // Step5. (x1, y1) = u1G + u2Q.만일 (x1, y1) = O이면 잘못된 서명이다.
   ecdsa_p256_t temp_G;  // G값을 저장하고 계산에 이용할 임시 변수 temp_G 선언
   ecdsa_p256_t temp_Q;  // Q값을 저장하고 계산에 이용할 임시 변수 temp_Q 선언
   memcpy(&temp_G.x,&G.x,ECDSA_P256/8);    // G의 x값 복사
   memcpy(&temp_G.y,&G.y,ECDSA_P256/8);    // G의 y값 복사
   memcpy(&temp_Q.x,_Q->x,ECDSA_P256/8);   // Q의 x값 복사
   memcpy(&temp_Q.y,_Q->y,ECDSA_P256/8);   // Q의 y값 복사

   // u1G, u2Q를 0으로 초기화
   memset(u1G.x,0,ECDSA_P256/8);
   memset(u1G.y,0,ECDSA_P256/8);
   memset(u2Q.x,0,ECDSA_P256/8);
   memset(u2Q.y,0,ECDSA_P256/8);

   ecc_mul(&temp_G, u1, &u1G);
   ecc_mul(&temp_Q, u2, &u2Q);
   if (ecc_add(&u1G, &u2Q, &XY)==1)
       return ECDSA_SIG_INVALID;

   // Step6. r = x1 (mod n)이면 올바른 서명이다.
   mpz_import(x1, ECDSA_P256/8, 1, 1, 1, 0, XY.x);
   mpz_mod(v, x1, n);   // v = x1 mod n

   // v!=r 이면 전자서명 인증실패
   if(mpz_cmp(v,r)!=0)
       return ECDSA_SIG_MISMATCH;

   mpz_clears(r, s, temp_e, temp, w, u1, u2, x1, v, NULL);
   return 0;
}
