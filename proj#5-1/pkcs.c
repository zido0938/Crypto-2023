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
#include <string.h>
#include <gmp.h>
#include "pkcs.h"
#include "sha2.h"

void sha(const void *data, size_t len, unsigned char *digest, int sha2_ndx)
{
    switch(sha2_ndx){
        case SHA224:
            sha224(data,len,digest);
            break;
        case SHA256:
            sha256(data,len,digest);
            break;
        case SHA384:
            sha384(data,len,digest);
            break;
        case SHA512:
            sha512(data,len,digest);
            break;
        case SHA512_224:
            sha512_224(data,len,digest);
            break;
        case SHA512_256:
            sha512_256(data,len,digest);
            break;
    }
}
/*
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */
void rsa_generate_key(void *_e, void *_d, void *_n, int mode)
{
    mpz_t p, q, lambda, e, d, n, gcd;
    gmp_randstate_t state;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     */
    do {
        do {
            mpz_urandomb(p, state, RSAKEYSIZE/2);
            mpz_setbit(p, 0);
            mpz_setbit(p, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(p, 50) == 0);
        do {
            mpz_urandomb(q, state, RSAKEYSIZE/2);
            mpz_setbit(q, 0);
            mpz_setbit(q, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(q, 50) == 0);
        /*
         * If we select e = 65537, it should be relatively prime to Lambda(n)
         */
        if (mode == 0) {
            mpz_sub_ui(p, p, 1);
            if (mpz_gcd_ui(gcd, p, 65537) != 1)
                continue;
            else
                mpz_add_ui(p, p, 1);
            mpz_sub_ui(q, q, 1);
            if (mpz_gcd_ui(gcd, q, 65537) != 1)
                continue;
            else
                mpz_add_ui(q, q, 1);
        }
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE-1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(lambda, p, q);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else do {
        mpz_urandomb(e, state, RSAKEYSIZE);
        mpz_gcd(gcd, e, lambda);
    } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE/8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE/8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE/8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, lambda, e, d, n, gcd, NULL);
}

/*
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns PKCS_MSG_OUT_OF_RANGE, otherwise returns 0 for success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n)
{
    mpz_t m, k, n;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE/8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE/8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE/8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return PKCS_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE/8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}
static unsigned char *mgf(const unsigned char *seed, size_t seedLen, unsigned char *mask, size_t maskLen, int sha2_ndx)
{
    uint32_t i, count, c;
    size_t hLen = SHA2SIZE[sha2_ndx];
    unsigned char *mgfIn, *msg;
    
    /*
     * maskLen 이 2^32*hLen보다큰지 확인
     */
    if (maskLen > 0x0100000000 * hLen)
        return NULL;
    
    if ((mgfIn = (unsigned char *)malloc(seedLen + 4)) == NULL)
        return NULL;
    memcpy(mgfIn, seed, seedLen);
    count = maskLen / hLen + (maskLen % hLen ? 1 : 0);
    if ((msg = (unsigned char *)malloc(count * hLen)) == NULL){
        free(mgfIn);
        return NULL;
    }
    for (i = 0; i < count; i++) {
        c = i;
        mgfIn[seedLen + 3] = c & 0x000000ff; c >>= 8;
        mgfIn[seedLen + 2] = c & 0x000000ff; c >>= 8;
        mgfIn[seedLen + 1] = c & 0x000000ff; c >>= 8;
        mgfIn[seedLen] = c & 0x000000ff;
        (*sha)(mgfIn, seedLen + 4, msg + i * hLen,sha2_ndx);
    }
    
    memcpy(mask, msg, maskLen);
    free(mgfIn);
    free(msg);
    return mask;
}

int rsaes_oaep_encrypt(const void *m, size_t mLen, const void *label, const void *e, const void *n, void *c, int sha2_ndx) {
    
    if (strlen(label) >= 0x1fffffffffffffff)
        return PKCS_LABEL_TOO_LONG;
    // 라벨 길이 제한 초과(2^64비트 즉, 2^61바이트보다 크면 안됨)
    
    size_t hLen;
    unsigned char *lHash;
    
    hLen = SHA2SIZE[sha2_ndx];
    lHash = malloc(sizeof(unsigned char) * hLen);
    
    sha(label, strlen(label), lHash, sha2_ndx);
    
    
    if (mLen > RSAKEYSIZE / 8 - 2 * hLen - 2)
        return PKCS_MSG_TOO_LONG;
    // 메세지가 너무 길면 오류메세지 출력
    
    // psLen 즉 PaddingString을 생성
    size_t psLen = RSAKEYSIZE / 8 - 2 - 2 * hLen - mLen;
    
    unsigned char *PaddingString = calloc(psLen, sizeof(unsigned char));
    
    
    // 주어진 변수들 + psLen으로 DB(DataBlock)생성
    size_t dbLen = hLen + psLen + 1 + mLen;
    unsigned char *DataBlock = malloc(sizeof(unsigned char) * dbLen);
    
    // memcpy를 활용하여 DataBlock에 순서대로 lHash, PaddingStirng, 01(0x01), Message를 붙여준다
    unsigned char temp[1] = {0x01};
    memcpy(DataBlock, lHash, hLen);
    memcpy(DataBlock + hLen, PaddingString, psLen);
    memcpy(DataBlock + hLen + psLen, temp, 1);
    memcpy(DataBlock + hLen + psLen + 1, m, mLen);
    
    // 난수 byte 문자열 seed를 생성. 이떄 arc4random_buf를 사용 (openssl사용시 RAND_BYTE사용가능)
    unsigned char *seed = malloc(sizeof(unsigned char) * hLen);
    arc4random_buf(seed, hLen);
    
    // seed를 MGF에 통과시켜 dbMask를 생성
    unsigned char *dbMask = malloc(sizeof(unsigned char) * dbLen);
    mgf( seed, hLen,dbMask, dbLen, sha2_ndx);
    
    // mgf(dbMask) +(XOR) DataBlock으로 MaskedDataBlock을 생성
    unsigned char *MaskedDataBlock = malloc(sizeof(unsigned char) * dbLen);
    for (int i = 0; i < dbLen; i++) {
        MaskedDataBlock[i] = dbMask[i] ^ DataBlock[i];
    }
    
    // MaskedDataBlock을 MGF에 통과하여 seedMask를 생성
    unsigned char *seedMask = malloc(sizeof(unsigned char) * hLen);
    mgf(MaskedDataBlock, dbLen, seedMask, hLen, sha2_ndx);
    
    // mgf(seedMask) +(XOR) seed로 MaskedSeed을 생성
    unsigned char *MaskedSeed = malloc(sizeof(unsigned char) * hLen);
    for (int i = 0; i < hLen; i++) {
        MaskedSeed[i] = seedMask[i] ^ seed[i];
    };
    
    // Encoded Message에 차례대로 00(0x00), MaskedSeed, MaskedDataBlock을 붙여준다
    unsigned char *EncodedMessage = malloc(sizeof(unsigned char) * RSAKEYSIZE / 8);
    temp[0] = 0x00;
    memcpy(EncodedMessage, temp, 1);
    memcpy(EncodedMessage + 1, MaskedSeed, hLen);
    memcpy(EncodedMessage + 1 + hLen, MaskedDataBlock, dbLen);
    
    // EM를 rsa로 암호화
    int rsa_result = rsa_cipher(EncodedMessage, e, n);
    if(rsa_result != 0)
        return rsa_result;
    
    // 암호화된 EM을 c에 저장
    memcpy(c, EncodedMessage, (RSAKEYSIZE / 8));
    
    // 메모리 할당 해제
    free(lHash);
    free(PaddingString);
    free(DataBlock);
    free(MaskedDataBlock);
    free(seed);
    free(MaskedSeed);
    free(dbMask);
    free(seedMask);
    free(EncodedMessage);
    return 0;
}

int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d, const void *n, const void *c, int sha2_ndx) {
    
    if(strlen(label) >= 0x1fffffffffffffff)
        return PKCS_LABEL_TOO_LONG;
    // 라벨 길이 제한 초과
    
    //RSA 복호화
    unsigned char *encodedMessage = malloc(sizeof(unsigned char) * (RSAKEYSIZE/8));
    memcpy(encodedMessage, c, sizeof(unsigned char) * (RSAKEYSIZE/8));
    
    int rsa_result = rsa_cipher(encodedMessage, d, n);
    if(rsa_result != 0)
        return rsa_result;
    
    if(encodedMessage[0] != 0x00)
        return PKCS_INITIAL_NONZERO;
    // Encoded Message의 첫번째 바이트가 0이 아님
    
    // 복호화 과정 - 기존 seed, dataBlock 복원
    unsigned char *maskedSeed = malloc(sizeof(unsigned char) * SHA2SIZE[sha2_ndx]);
    memcpy(maskedSeed, encodedMessage + 1, sizeof(unsigned char) * SHA2SIZE[sha2_ndx]);
    
    unsigned char *maskedDataBlock = malloc(sizeof(unsigned char) * (RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1));
    memcpy(maskedDataBlock, encodedMessage + SHA2SIZE[sha2_ndx] + 1, sizeof(unsigned char) * (RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1));
    
    unsigned char *seed = malloc(sizeof(unsigned char) * SHA2SIZE[sha2_ndx]);
    unsigned char *dataBlock = malloc(sizeof(unsigned char) * (RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1));
    mgf( maskedDataBlock, RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1,seed, SHA2SIZE[sha2_ndx], sha2_ndx);
    
    for (int i = 0; i < SHA2SIZE[sha2_ndx]; ++i)
        seed[i] ^= maskedSeed[i];
    
    mgf(seed, SHA2SIZE[sha2_ndx],dataBlock, RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1, sha2_ndx);
    
    for (int i = 0; i < RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1; ++i)
        dataBlock[i] ^= maskedDataBlock[i];
    
    // 원래의 메세지 복원
    unsigned char *labelHash = malloc(sizeof(unsigned char) * SHA2SIZE[sha2_ndx]);
    memcpy(labelHash, dataBlock, sizeof(unsigned char) * SHA2SIZE[sha2_ndx]);
    
    unsigned char *labelHash_In = malloc(sizeof(unsigned char) * SHA2SIZE[sha2_ndx]);
    sha(label, strlen(label), labelHash_In,sha2_ndx);
    
    if(memcmp(labelHash, labelHash_In, SHA2SIZE[sha2_ndx]) != 0)
        return PKCS_HASH_MISMATCH; // label hash가 다름
    
    // padingString 확인(0x01이 맞는지)
    size_t ptr = SHA2SIZE[sha2_ndx];
    for(;ptr < RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1 && dataBlock[ptr] == 0x00; ++ptr);
    unsigned char divider = ptr < RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1 ? dataBlock[ptr] : 0x00;
    
    if(divider != 0x01)
        return PKCS_INVALID_PS;
    // paddingString 뒤에 붙는 값이 0x01이 아님
    
    // 최종 메세지 복호화
    *mLen = RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1 - ++ptr;
    memcpy(m, dataBlock + ptr, sizeof(char) * *mLen);
    
    // 메모리 할당 해제
    free(dataBlock);
    free(encodedMessage);
    free(maskedDataBlock);
    free(seed);
    free(maskedSeed);
    free(labelHash);
    free(labelHash_In);
    return 0;
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s, int sha2_ndx)
{
    if(mLen > 0x1fffffffffffffff)
        return PKCS_MSG_TOO_LONG;
    // mLen길이 제한 초과(2^64비트 즉, 2^61바이트보다 크면 안됨)
    
    // mHash 생성
    unsigned char mHash[SHA2SIZE[sha2_ndx]];
    sha(m, mLen, mHash,sha2_ndx);
    
    // arc4random_buf로 난수의 salt 생성
    unsigned salt[SHA2SIZE[sha2_ndx]]; // salt의 길이는 해시 길이와 같음
    arc4random_buf(salt, SHA2SIZE[sha2_ndx]);
    
    // 0x00(00) 8바이트와 mHash, salt를 이어붙여 mPrime(m')생성
    unsigned char mPrime[8+2*SHA2SIZE[sha2_ndx]];
    memset(mPrime, 0x00, 8);
    memcpy(mPrime+8, mHash, SHA2SIZE[sha2_ndx]);
    memcpy(mPrime+8+SHA2SIZE[sha2_ndx], salt, SHA2SIZE[sha2_ndx]);
    
    // mPrime을 해시를 통해 H생성
    unsigned char H[SHA2SIZE[sha2_ndx]];
    sha(mPrime, 8+2*SHA2SIZE[sha2_ndx], H,sha2_ndx);
    
    //DB 생성
    int DB_SIZE = RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1;
    unsigned char DB[DB_SIZE];
    
    memset(DB, 0, DB_SIZE - SHA2SIZE[sha2_ndx] -1); // ps
    DB[DB_SIZE-SHA2SIZE[sha2_ndx]-1] = 0x01; // 0x01
    memcpy(DB + DB_SIZE-SHA2SIZE[sha2_ndx], salt, SHA2SIZE[sha2_ndx]); // salt
    
    // H를 MGF에 통과시켜 H마스크 생성
    unsigned char MaskedH[DB_SIZE];
    mgf(H, SHA2SIZE[sha2_ndx], MaskedH, DB_SIZE, sha2_ndx);
    
    // MaskedH와 DB XOR 연산하여 maskedDB생성
    unsigned char maskedDB[DB_SIZE];
    for(int i=0; i<DB_SIZE; i++){
        maskedDB[i] = DB[i] ^ MaskedH[i];
    }
    
    if(DB_SIZE + SHA2SIZE[sha2_ndx] + 1 > RSAKEYSIZE/8)
        return PKCS_HASH_TOO_LONG;
    // H가 EM의 길이보다 크면 수용불가능
    
    //EM 생성
    unsigned char EM[RSAKEYSIZE/8];
    memcpy(EM, maskedDB, DB_SIZE);
    memcpy(EM+DB_SIZE, H, SHA2SIZE[sha2_ndx]);
    EM[RSAKEYSIZE/8-1] = 0xbc;
    
    // EM의 첫 비트가 1이면 0으로 바꿔줌
    if((EM[0]>>7) & 1) EM[0] = 0x00;
    
    // 키 사용하여 암호화
    if(rsa_cipher(EM, d, n) == PKCS_MSG_OUT_OF_RANGE)
        return PKCS_MSG_OUT_OF_RANGE;
    memcpy(s, EM, RSAKEYSIZE/8);
    
    return 0;
}
/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e,n)으로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s, int sha2_ndx)
{
    unsigned char EM[RSAKEYSIZE/8];
    memcpy(EM, s, RSAKEYSIZE/8);
    
    // 키 사용하여 복호화
    if(rsa_cipher(EM, e, n) == PKCS_MSG_OUT_OF_RANGE)
        return PKCS_MSG_OUT_OF_RANGE;
    
    // 오류 검증
    if(EM[RSAKEYSIZE/8-1] ^ 0xbc) return PKCS_INVALID_LAST;
    if((EM[0] >> 7) & 1) return PKCS_INVALID_INIT;
    
    // maskedDB 추출
    int DB_SIZE = RSAKEYSIZE/8 - SHA2SIZE[sha2_ndx] - 1;
    unsigned char maskedDB[DB_SIZE];
    memcpy(maskedDB, EM, DB_SIZE);
    
    // H 추출
    unsigned char H[SHA2SIZE[sha2_ndx]];
    memcpy(H, EM+DB_SIZE, SHA2SIZE[sha2_ndx]);
    
    // MaskedH 복원
    unsigned char MaskedH[DB_SIZE];
    mgf(H, SHA2SIZE[sha2_ndx], MaskedH, DB_SIZE, sha2_ndx);
    
    // DB 복원
    unsigned char DB[DB_SIZE];
    DB[0] = 0x00;
    for(int i=1; i<DB_SIZE; i++){
        DB[i] = maskedDB[i] ^ MaskedH[i];
    }
    
    // salt 복원
    unsigned char salt[SHA2SIZE[sha2_ndx]];
    memcpy(salt, DB+DB_SIZE-SHA2SIZE[sha2_ndx], SHA2SIZE[sha2_ndx]);
    
    // DB 앞 부분이 0x0000..00||0x01과 일치하는지 확인
    if(DB[DB_SIZE-SHA2SIZE[sha2_ndx]-1] ^ 0x01) return  PKCS_INVALID_PD2 ;
    for(int i=0; i<DB_SIZE - SHA2SIZE[sha2_ndx] - 1; i++){
        if(DB[i] ^ 0x00) return PKCS_INVALID_PD2;
    }
    
    // 주어진 m으로 mHash 생성
    unsigned char mHash[SHA2SIZE[sha2_ndx]];
    sha(m, mLen, mHash,sha2_ndx);
    
    // mPrime 생성
    unsigned char mPrime[8+2*SHA2SIZE[sha2_ndx]];
    memset(mPrime, 0x00, 8);
    memcpy(mPrime+8, mHash, SHA2SIZE[sha2_ndx]);
    memcpy(mPrime+8+SHA2SIZE[sha2_ndx], salt, SHA2SIZE[sha2_ndx]);
    
    // mPrime Hash 생성
    unsigned char mPrimeHash[SHA2SIZE[sha2_ndx]];
    sha(mPrime, 8+2*SHA2SIZE[sha2_ndx], mPrimeHash,sha2_ndx);
    
    // mPrime Hash와 H 비교
    if(memcmp(mPrimeHash, H, SHA2SIZE[sha2_ndx]) != 0) return PKCS_HASH_MISMATCH;
    
    return 0;
}
