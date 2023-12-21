/*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
/*
 * AES128 (128 비트 키, 10 라운드): Nb = 4, Nk = 4, Nr = 10
 * AES192 (192 비트 키, 12 라운드): Nb = 4, Nk = 6, Nr = 12
 * AES256 (256 비트 키, 14 라운드): Nb = 4, Nk = 8, Nr = 14
 */
#define Nb 4  /* Number of columns (32-bit words) comprising the State */
#define Nk 4  /* Number of 32-bit words comprising the Cipher Key */
#define Nr 10 /* Number of rounds */

#define BLOCKLEN (4*Nb)           /* block length in bytes */
#define KEYLEN (4*Nk)             /* key length in bytes */
#define RNDKEYLEN (Nb*(Nr+1))     /* round key length in words */

#define XTIME(a) (((a)<<1) ^ ((((a)>>7) & 1) * 0x1b))

#define ENCRYPT 1
#define DECRYPT 0

void KeyExpansion(const uint8_t *key, uint32_t *roundKey);
void Cipher(uint8_t *state, const uint32_t *roundKey, int mode);

#endif
