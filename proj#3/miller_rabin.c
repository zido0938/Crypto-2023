/*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */

/*
 * Last modified by Ji Hyeon Do
 * Data : 2023/10/11
 * Name : Ji Hyeon Do
 * Department(Division) : Computer science & engineering
 * Student_Number: 2021004866
 */

#include "miller_rabin.h"

/*
 * mod_add() - computes a+b mod m
 * a와 b가 m보다 작다는 가정하에서 a+b >= m이면 결과에서 m을 빼줘야 하므로
 * 오버플로가 발생하지 않도록 a-(m-b)를 계산하고, 그렇지 않으면 그냥 a+b를 계산하면 된다.
 * a+b >= m을 검사하는 과정에서 오버플로가 발생할 수 있으므로 a >= m-b를 검사한다.
 */
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{
    a = a % m;
    b = b % m;
    if(a>=m-b)
        return a-(m-b); // if(a+b>=m) -> if(a>=m-b)
    return a+b;
}

/*
 * mod_sub() - computes a-b mod m
 * 만일 a < b이면 결과가 음수가 되므로 m을 더해서 양수로 만든다.
 */
uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m)
{
     a = a % m;
     b = b % m;
     if(a < b)
         return m-(b-a); // == return a-b+m -> m-(b-a)
     return a-b;
}

/*
 * mod_mul() - computes a*b mod m
 * a*b에서 오버플로가 발생할 수 있기 때문에 덧셈을 사용하여 빠르게 계산할 수 있는
 * "double addition" 알고리즘을 사용한다. 그 알고리즘은 다음과 같다.
 *     r = 0;
 *     while (b > 0) {
 *         if (b & 1)
 *             r = mod_add(r, a, m);
 *         b = b >> 1;
 *         a = mod_add(a, a, m);
 *     }
 */
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
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
 * a^b에서 오버플로가 발생할 수 있기 때문에 곱셈을 사용하여 빠르게 계산할 수 있는
 * "square multiplication" 알고리즘을 사용한다. 그 알고리즘은 다음과 같다.
 *     r = 1;
 *     while (b > 0) {
 *         if (b & 1)
 *             r = mod_mul(r, a, m);
 *         b = b >> 1;
 *         a = mod_mul(a, a, m);
 *     }
 */
uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
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
 * Miller-Rabin Primality Testing against small sets of bases
 *
 * if n < 2^64,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37.
 *
 * if n < 3,317,044,064,679,887,385,961,981,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, and 41.
 */
const uint64_t a[BASELEN] = {2,3,5,7,11,13,17,19,23,29,31,37};

/*
 * miller_rabin() - Miller-Rabin Primality Test (deterministic version)
 *
 * n > 3, an odd integer to be tested for primality
 * It returns PRIME if n is prime, COMPOSITE otherwise.
 */

/*
 * isComposite() - Test(n), n이 소수인지 합성수인지 확인(소수일확률이 높다 - 꼭 소수라는 것은 아니다)
 * 만약 합성수라면 1을 반환하고, 아니라면 0을 반환한다
 *
 */
int isComposite(uint64_t a, uint64_t q, uint64_t k, uint64_t n){
    uint64_t tmp = mod_pow(a, q, n);
    if(tmp == 1 || tmp == n-1)
        return 0;
    for(uint64_t j=1; j<k; j++){
        tmp = mod_mul(tmp,tmp,n);
        if(tmp == n-1)
            return 0;
    }
    return 1;
}

int miller_rabin(uint64_t n)
{
    if(n == 2)
        return 1;
        else if(n < 2 || n % 2 == 0)
            return 0;
        uint64_t k = 0, q = n-1;
        while(!(q & 1)){ // (n-1) = (2^k)q 인 k와 q를 찾을때까지 비트를 밀어가며 반복 계산
            k++;
            q = q >> 1;
        }
        for(int i=0; (i<BASELEN && a[i]<n-1); i++){
            if(isComposite(a[i], q, k, n))
                return 0;
        }
        return 1;
}
