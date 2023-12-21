/*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
#ifndef _PKCS_H_
#define _PKCS_H_

#define RSAKEYSIZE 2048

/*
 * SHA-2 function index list
 */
#define SHA224      0
#define SHA256      1
#define SHA384      2
#define SHA512      3
#define SHA512_224  4
#define SHA512_256  5

static const size_t SHA2SIZE[6]={
    28,32,48,64,28,32
};

/*
 * Error message list
 */
#define PKCS_MSG_OUT_OF_RANGE   1
#define PKCS_MSG_TOO_LONG       2
#define PKCS_LABEL_TOO_LONG     3
#define PKCS_INITIAL_NONZERO    4
#define PKCS_HASH_MISMATCH      5
#define PKCS_INVALID_PS         6
#define PKCS_HASH_TOO_LONG      7
#define PKCS_INVALID_LAST       8
#define PKCS_INVALID_INIT       9
#define PKCS_INVALID_PD2        10

void rsa_generate_key(void *e, void *d, void *n, int mode);
int rsaes_oaep_encrypt(const void *msg, size_t len, const void *label, const void *e, const void *n, void *c, int sha2_ndx);
int rsaes_oaep_decrypt(void *msg, size_t *len, const void *label, const void *d, const void *n, const void *c, int sha2_ndx);
int rsassa_pss_sign(const void *msg, size_t len, const void *d, const void *n, void *sig, int sha2_ndx);
int rsassa_pss_verify(const void *msg, size_t len, const void *e, const void *n, const void *sig, int sha2_ndx);

#endif
