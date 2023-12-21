/*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
#ifndef _EUCLID_H_
#define _EUCLID_H_

#include <stdint.h>

int gcd(int a, int b);
int xgcd(int a, int b, int *x, int *y);
int mul_inv(int a, int m);
uint64_t umul_inv(uint64_t a, uint64_t m);
uint16_t gf16_mul(uint16_t a, uint16_t b);
uint16_t gf16_pow(uint16_t a, uint16_t b);
uint16_t gf16_inv(uint16_t a);

#endif
