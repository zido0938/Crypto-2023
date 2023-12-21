/*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
/*
 * Last modified by Ji Hyeon Do
 * Data : 2023/09/19
 * Name : Ji Hyeon Do
 * Department(Division) : Computer science & engineering
 * Student_Number: 2021004866
 */

#include "euclid.h"
#define swap(a,b,type) do{type tmp=a; a=b; b=tmp;}while(0);
/*
 * gcd() - Euclidean algorithm
 *
 * 유클리드 알고리즘 gcd(a,b) = gcd(b,a mod b)를 사용하여 최대공약수를 계산한다.
 * 만일 a가 0이면 b가 최대공약수가 된다. 그 반대도 마찬가지이다.
 * a, b가 모두 음이 아닌 정수라고 가정한다.
 * 재귀함수 호출을 사용하지 말고 while 루프를 사용하여 구현하는 것이 빠르고 좋다.
 */

int gcd(int a, int b) {
    while (b != 0) {
        int temp = a;
        a = b;
        b = temp % b;
    }
    return a;
}

/*
 * xgcd() - Extended Euclidean algorithm
 *
 * 확장유클리드 알고리즘은 두 수의 최대공약수 gcd(a,b) = ax + by 식을
 * 만족하는 x와 y를 계산하는 알고리즘이다. 강의노트를 참조하여 구현한다.
 * a, b가 모두 음이 아닌 정수라고 가정한다.
 */
int xgcd(int a, int b, int *x, int *y)
{
    int d0 = a, d1 = b, q, x0=1, x1=0, y0=0, y1=1;

    while(d1){
        q = d0/d1;
        d0 = d0 - q*d1; swap(d0,d1,int); // (d0,d1) = (d1,d0%d1)
        x0 = x0 - q*x1; swap(x0,x1,int); // xi+1 = xi-1 - q*xi
        y0 = y0 - q*y1; swap(y0,y1,int); // yi+1 = yi-1 - q*yi
    }

    *x = x0, *y = y0;
    return d0; // a와 b의 최대공약수
}

/*
 * mul_inv() - computes multiplicative inverse a^-1 mod m
 *
 * 모듈로 m에서 a의 곱의 역인 a^-1 mod m을 구한다.
 * 만일 역이 존재하지 않으면 0을 리턴한다.
 * 확장유클리드 알고리즘을 변형하여 구현한다. 강의노트를 참조한다.
 */
int mul_inv(int a, int m)
{
    int x, y;
    if(xgcd(a,m,&x,&y) != 1) return 0; // 서로소가 아니면 역을 구할 수 없음
    return x<0 ? x+m : x;
}

/*
 * umul_inv() - computes multiplicative inverse a^-1 mod m
 *
 * 입력이 unsigned 64 비트 정수일 때 모듈로 m에서 a의 곱의 역인 a^-1 mod m을 구한다.
 * 만일 역이 존재하지 않으면 0을 리턴한다. 확장유클리드 알고리즘을 변형하여 구현한다.
 * 입출력 모두가 unsigned 64 비트 정수임에 주의한다.
 */
uint64_t umul_inv(uint64_t a, uint64_t m)
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

uint16_t gf16_xtime(uint16_t x) {
    return (x << 1) ^ ((x >> 15) & 1 ? 0x2B : 0);  // 0x2B == x^5+x^3+x+1
}

/*
 * gf16_mul(a, b) - a * b mod x^16+x^5+x^3+x+1
 *
 * 15차식 다항식 a와 b를 곱하고 결과를 16차식 x^16+x^5+x^3+x+1로 나눈 나머지를 계산한다.
 * x^16 = x^5+x^3+x+1 (mod x^16+x^5+x^3+x+1) 특성을 이용한다.
 */
uint16_t gf16_mul(uint16_t a, uint16_t b)
{
    uint16_t r = 0;
    
    while(b>0){
        if(b&1) r=r^a;
        b = b >> 1;
        a = gf16_xtime(a);
    }
    
    return r;
}

/*
 * gf16_pow(a,b) - a^b mod x^16+x^5+x^3+x+1
 *
 * 15차식 다항식 a를 b번 지수승한 결과를 16차식 x^16+x^5+x^3+x+1로 나눈 나머지를 계산한다.
 * gf16_mul()과 "Square Multiplication" 알고리즘을 사용하여 구현한다.
 */
uint16_t gf16_pow(uint16_t a, uint16_t b)
{
    uint16_t ans = 1;
    while(b>0){
        if(b&1) ans = gf16_mul(ans,a); // b가 홀수라면 a를 곱해준다.
        a = gf16_mul(a,a); // a == a^2으로 만들어준다.
        b >>= 1; // shift 연산으로 2를 나눠준다.
    }
    return ans;
}

/*
 * gf16_inv(a) - a^-1 mod x^16+x^5+x^3+x+1
 *
 * 모둘러 x^16+x^5+x^3+x+1에서 a의 역을 구한다.
 * 역을 구하는 가장 효율적인 방법은 다항식 확장유클리드 알고리즘을 사용하는 것이다.
 * 다만 여기서는 복잡성을 피하기 위해 느리지만 알기 쉬운 지수를 사용하여 구현하였다.
 */
uint16_t gf16_inv(uint16_t a)
{
    return gf16_pow(a, 0xfffe);
}
