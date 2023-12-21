/*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
/*
 * Last modified by Ji Hyeon Do
 * Data : 2023/10/19
 * Name : Ji Hyeon Do
 * Department(Division) : Computer science & engineering
 * Student_Number: 2021004866
 */
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include "mRSA.h"

#define swap(a,b,type) do{type tmp=a; a=b; b=tmp;}while(0);

/*
 * mod_add() - computes a + b mod m
 */
static uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{
    a = a % m;
    b = b % m;
    if(a>=m-b)
        return a-(m-b); // if(a+b>=m) -> if(a>=m-b)
    return a+b;
}

/*
 * mod_mul() - computes a * b mod m
 */
static uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = 0;
        while(b > 0){
            if(b & 1)
                r = mod_add(r, a, m);
            b = b >> 1;
            a = mod_add(a, a, m);
        }
        return r;
}

/*
 * mod_pow() - computes a^b mod m
 */
static uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = 1;
        while(b > 0){
            if(b & 1)
                r = mod_mul(r, a, m);
            b = b >> 1;
            a = mod_mul(a, a, m);
        }
        return r;
}

/*
 * gcd() - Euclidean algorithm
 */
static uint64_t gcd(uint64_t a, uint64_t b)
{
    uint64_t tmp;
    while(b > 0){
        tmp = b;
        b = a % b;
        a = tmp;
    }
    return a;
}

/*
 * mul_inv() - computes multiplicative inverse a^-1 mod m
 * It returns 0 if no inverse exist.
 */
static uint64_t mul_inv(uint64_t a, uint64_t m)
{
    uint64_t d0 = a, d1 = m, q;
    long long x0 = 1, x1 = 0; // 음수를 고려하여 Long long 으로 지정

    while(d1 > 1){
        q = d0/d1;
        d0 = d0 - q*d1; swap(d0,d1,uint64_t); // (d1,d0%d1)
        x0 = x0 - (long long)q*x1; swap(x0,x1,long long); // (x1, x0-q*x1)
    }

    if(d1 == 1) return x1>0 ? (uint64_t)x1 : m-(uint64_t)(-x1); // 만약 음수라면 양수로 변환해준다
    else return 0;
}

/*
 * Miller-Rabin Primality Testing against small sets of bases
 *
 * if n < 2^64,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37.
 *
 * if n < 3317044064679887385961981,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, and 41.
 */
static const uint64_t a[BASELEN] = {2,3,5,7,11,13,17,19,23,29,31,37};

/*
 * miller_rabin() - Miller-Rabin Primality Test (deterministic version)
 *
 * n > 3, an odd integer to be tested for primality
 * It returns 1 if n is prime, 0 otherwise.
 */
static int isComposite(uint64_t a, uint64_t q, uint64_t k, uint64_t n){
    uint64_t tmp = mod_pow(a, q, n);
    if(tmp == 1 || tmp == n-1)
        return PRIME;
    for(uint64_t j=1; j<k; j++){
        tmp = mod_mul(tmp,tmp,n);
        if(tmp == n-1)
            return PRIME;
    }
    return COMPOSITE;
}

static int miller_rabin(uint64_t n)
{
    if(n == 2)
        return PRIME;
    else if(n < 2 || n % 2 == 0)
        return COMPOSITE;
    uint64_t k = 0, q = n-1;
    while(!(q & 1)){ // (n-1) = (2^k)q 인 k와 q를 찾을때까지 비트를 밀어가며 반복 계산
        k++;
        q = q >> 1;
    }
    for(int i=0; (i<BASELEN && a[i]<n-1); i++){
        if(isComposite(a[i], q, k, n) == COMPOSITE)
            return COMPOSITE;
    }
    return PRIME;
}

/*
 * mRSA_generate_key() - generates mini RSA keys e, d and n
 *
 * Carmichael's totient function Lambda(n) is used.
 */
void mRSA_generate_key(uint64_t *e, uint64_t *d, uint64_t *n)
{
    uint64_t p = 0, q = 0;
    *e = (1 << 16) + 1; // 65537
    while(1){
        arc4random_buf(&p, sizeof(uint32_t)); // 난수 중 2^32미만인 난수만 생성
        arc4random_buf(&q, sizeof(uint32_t));
        p |= 0x80000001, q |= 0x80000001; // or 연산을통해 항상 홀수로 만들어준다. 이러면 항상 2^31보다 크거나 같은 홀수가 된다.
        if(p*q < MINIMUM_N || miller_rabin(p) != PRIME || miller_rabin(q) != PRIME) continue;
        uint64_t lambda = (p-1) * (q-1) / gcd(p-1, q-1);
        if(*e >= lambda || gcd(*e, lambda) != 1) continue; // 람다이상이면서 서로소
        *d = mul_inv(*e, lambda); // ed mod lamda
        *n = p * q;
        break;
    }
}
/* e값을 랜덤으로 지정
 void mRSA_generate_key(uint64_t *e, uint64_t *d, uint64_t *n) {
     uint64_t p = 0, q = 0;
     while (1) {
         arc4random_buf(&p, sizeof(uint32_t));
         arc4random_buf(&q, sizeof(uint32_t);
         arc4random_buf(e, sizeof(uint32_t)); // Randomly set e
         p |= 0x80000001;
         q |= 0x80000001;
         *e |= 1; // Ensure e is an odd number
         if (p * q < MINIMUM_N || miller_rabin(p) != PRIME || miller_rabin(q) != PRIME) continue;
         uint64_t lambda = (p - 1) * (q - 1) / gcd(p - 1, q - 1);
         if (*e >= lambda || gcd(*e, lambda) != 1) continue;
         *d = mul_inv(*e, lambda);
         *n = p * q;
         break;
     }
 }
 */

/*
 * mRSA_cipher() - compute m^k mod n
 *
 * If data >= n then returns 1 (error), otherwise 0 (success).
 */
int mRSA_cipher(uint64_t *m, uint64_t k, uint64_t n)
{
    if(*m >= n) // m 이 n보다 크면 메세지가 손실되므로 강제 종료시킴.
        return 1;
    *m = mod_pow(*m, k, n); // 키(k,n)
    return 0;
}
