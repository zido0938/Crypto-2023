/*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
#ifndef _MILLER_RABIN_H_
#define _MILLER_RABIN_H_

#include <stdint.h>
#include <stdio.h>

#define BASELEN 12
#define PRIME 1
#define COMPOSITE 0

uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m);
uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m);
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m);
uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m);
int miller_rabin(uint64_t n);

#endif
