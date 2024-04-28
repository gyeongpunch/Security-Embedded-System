#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>
typedef unsigned char U8;
typedef unsigned int U32;
#define BYTES 16
#define BITS 128
int BN_xor(BIGNUM *b_r, int bits, const BIGNUM *b_a, const BIGNUM *b_b)
{
   //error
   if(b_r==NULL || b_a == NULL || b_b == NULL) 
      return 0;
   //bytes = bits / 8
   int i, bytes = bits >> 3;
   //calloc for type casting(BIGNUM to U8)
   U8 *r = (U8*)calloc(bytes,sizeof(U8));
   U8 *a = (U8*)calloc(bytes,sizeof(U8));
   U8 *b = (U8*)calloc(bytes,sizeof(U8));
   //BN_num_bytes(a) : return a's bytes 
   int byte_a = BN_num_bytes(b_a);
   int byte_b = BN_num_bytes(b_b);
   //difference between A and B
   int dif = abs(byte_a-byte_b);
   //minimum
   int byte_min = (byte_a < byte_b)? byte_a : byte_b;
   //type casting(BIGNUM to U8)
   BN_bn2bin(b_a,a);
   BN_bn2bin(b_b,b);
   //xor compute
   for(i=1;i<=byte_min;i++)
      r[bytes - i] = a[byte_a - i] ^ b[byte_b - i];
   for(i=1;i<=dif;i++)
      r[bytes - byte_min - i] = (byte_a>byte_b)? a[dif-i] : b[dif-i];
   //type casting(U8 to BIGNUM)
   BN_bin2bn(r,bytes,b_r);
   //Free memory
   free(a);
   free(b);
   free(r);
   return 1;//correct
}
int Gen(AES_KEY *enckey, int bits)
{
    if (enckey == NULL || bits <= 0) return 0;
    int bytes = bits >> 3;

    BIGNUM *bn_key = BN_new();
    BN_rand(bn_key, bits, -1, 0);

    U8 *key_bytes = (U8*)calloc(bytes, sizeof(U8));
    BN_bn2bin(bn_key, key_bytes);

    AES_set_encrypt_key(key_bytes, bits, enckey);

    BN_free(bn_key);
    free(key_bytes);

    return 1;
}

U8 ** Enc(AES_KEY *k, int bits, U8 *m)
{
    int i, bytes = bits >> 3;
    U8 **c = (U8 **)calloc(2, sizeof(U8*));
    for (i = 0; i < 2; i++)
        c[i] = (U8 *)calloc(bytes, sizeof(U8));

    BIGNUM *bn_r = BN_new();
    BN_rand(bn_r, bits, -1, 0);

    U8 *r_bytes = (U8*)calloc(bytes, sizeof(U8));
    BN_bn2bin(bn_r, r_bytes);

    printf("r : ");
    for(i=0; i<BYTES; i++)
        printf("%02X", r_bytes[i]);
    printf("\n");

    memcpy(c[0], r_bytes, bytes);

    AES_encrypt(c[0], c[1], k);

    BIGNUM *bn_F_k_r = BN_new();
    BN_bin2bn(c[1], bytes, bn_F_k_r);

    printf("Fkr : ");
    for(i=0; i<BYTES; i++)
        printf("%02X", c[1][i]);
    printf("\n");

    BIGNUM *bn_m = BN_new();
    BN_bin2bn(m, bytes, bn_m);

    BN_xor(bn_F_k_r, bits, bn_F_k_r, bn_m);
    BN_bn2bin(bn_F_k_r, c[1]);

    BN_free(bn_r);
    free(r_bytes);
    BN_free(bn_F_k_r);
    BN_free(bn_m);

    return c;
}

U8 *Dec(AES_KEY *k, int bits, U8 **C)
{
    int bytes = bits >> 3;
    U8 *M = (U8*)calloc(bytes, sizeof(U8));

    AES_encrypt(C[0], M, k);

    BIGNUM *bn_F_k_C1 = BN_new();
    BN_bin2bn(M, bytes, bn_F_k_C1);

    printf("FkC : ");
    for(int i=0; i<BYTES; i++)
        printf("%02X", M[i]);
    printf("\n");

    BIGNUM *bn_C2 = BN_new();
    BN_bin2bn(C[1], bytes, bn_C2);

    BN_xor(bn_F_k_C1, bits, bn_F_k_C1, bn_C2);
    BN_bn2bin(bn_F_k_C1, M);

    M[bytes] = '\0';

    BN_free(bn_F_k_C1);
    BN_free(bn_C2);

    return M;
}
int main(int argc, char* argv[]) {
   int i;
   AES_KEY enckey; // AES encryption key
   U8 *m = (U8*)"CPA-secure";
   U8 *dec = (U8*)calloc(BYTES,sizeof(U8));
   
   Gen(&enckey,BITS);
   U8 **c = Enc(&enckey,BITS,m);
   U8 *d_m = Dec(&enckey,BITS,c);
   
   printf("C1 : ");
   for(i=0;i<BYTES;i++)
      printf("%02X",c[0][i]);
   printf("\n");
   printf("C2 : ");
   for(i=0;i<BYTES;i++)
      printf("%02X",c[1][i]);
   printf("\n");
   printf("Dec : %s\n", d_m);
   
   free(c[0]);
   free(c[1]);
   free(c);
   return 0;
}