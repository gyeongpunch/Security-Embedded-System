#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

typedef unsigned char U8;
typedef struct
{
    BIGNUM *d;
    BIGNUM *x;
    BIGNUM *y;
} BN_dxy;

BN_dxy BN_dxy_new(const BIGNUM *d, const BIGNUM *x, const BIGNUM *y)
{
    BN_dxy dxy;
    dxy.d = BN_new();
    dxy.x = BN_new();
    dxy.y = BN_new();
    if (d == NULL)
        return dxy;
    BN_copy(dxy.d, d);
    BN_copy(dxy.x, x);
    BN_copy(dxy.y, y);
    return dxy;
}

int BN_dxy_copy(BN_dxy *dxy, BIGNUM *d, BIGNUM *x, BIGNUM *y)
{
    BN_copy(dxy->d, d);
    BN_copy(dxy->x, x);
    BN_copy(dxy->y, y);
}

void BN_dxy_free(BN_dxy *dxy)
{
    BN_free(dxy->d);
    BN_free(dxy->x);
    BN_free(dxy->y);
}

BIGNUM *BN_Square_Multi(BIGNUM *x, BIGNUM *a, BIGNUM *n)
{
    BIGNUM *result = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *z = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    BN_one(z); // z = 1

    BN_mod(result, x, n, bn_ctx);

    for (int i = BN_num_bits(a) - 2; i >= 0; i--){
        BN_mod_mul(result, result, result, n, bn_ctx);

        if (BN_is_bit_set(a, i)){
            BN_mod_mul(result, result, x, n, bn_ctx);
        }
    }

    BN_free(temp);
    BN_free(z);

    return result;
}

BN_dxy BN_Ext_Euclid(BIGNUM *a, BIGNUM *b){
    BN_dxy dxy;
    BN_CTX *bn_ctx = BN_CTX_new();

    if (BN_is_zero(b)){
        dxy = BN_dxy_new(a, BN_value_one(), b);
        BN_CTX_free(bn_ctx);
        return dxy;
    }
    else{
        BIGNUM *div = BN_new();
        BIGNUM *rem = BN_new();
        BIGNUM *temp = BN_new();

        BN_div(div, rem, a, b, bn_ctx);
        BN_dxy result = BN_Ext_Euclid(b, rem);

        // temp = x' - [a/b] * y'
        BN_mul(temp, div, result.y, bn_ctx);
        BN_sub(temp, result.x, temp);

        BN_copy(result.x, result.y);
        BN_copy(result.y, temp);

        dxy = BN_dxy_new(result.d, result.x, result.y);

        BN_free(div);
        BN_free(rem);
        BN_free(temp);
        BN_free(result.d);
        BN_free(result.x);
        BN_free(result.y);
    }

    BN_CTX_free(bn_ctx);

    return dxy;
}

void RSA_setup(BIGNUM *pub_e, BIGNUM *pub_N, BIGNUM *priv){
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BN_dxy dxy;
    BIGNUM *N = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *ord = BN_new();
    BN_set_word(e, 3);

    // 소수 p, q
    while (1){
        BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
        BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);

        // N = p * q
        BN_mul(N, p, q, bn_ctx);

        // ord = (p-1) * (q-1)
        BN_sub(p, p, BN_value_one());
        BN_sub(q, q, BN_value_one());
        BN_mul(ord, p, q, bn_ctx);

        // (e * d) % ord == 1
        dxy = BN_Ext_Euclid(e, ord);
        if (BN_is_one(dxy.d))
            break;
    }

    BN_copy(pub_e, e);
    BN_copy(pub_N, N);

    BN_mod_inverse(priv, e, ord, bn_ctx);

    char *e_hex = BN_bn2hex(pub_e);
    char *N_hex = BN_bn2hex(pub_N);
    char *d_hex = BN_bn2hex(dxy.x);
    char *x_hex = BN_bn2hex(dxy.y);
    char *y_hex = BN_bn2hex(dxy.d);

    printf("e\t : %s\n", e_hex);
    printf("N\t : %s\n", N_hex);
    printf("dxy.y\t : %s\n", d_hex);
    printf("dxy.x\t : %s\n", x_hex);
    printf("dxy.d\t : %s\n\n", y_hex);

    OPENSSL_free(e_hex);
    OPENSSL_free(N_hex);
    OPENSSL_free(d_hex);
    OPENSSL_free(x_hex);
    OPENSSL_free(y_hex);
    BN_free(p);
    BN_free(q);
    BN_free(N);
    BN_free(e);
    BN_free(ord);
    BN_dxy_free(&dxy);
    BN_CTX_free(bn_ctx);
}

U8 * RSA_enc(const U8 * msg, BIGNUM * pub_e, BIGNUM * pub_N){   
    BIGNUM *C = BN_new();
    BIGNUM *M = BN_new();
    BN_bin2bn(msg, strlen(msg), M);
    BN_mod_exp(C, M, pub_e, pub_N, BN_CTX_new());
    U8 *cipher = BN_bn2hex(C);
    
    // Free resources
    BN_free(C);
    BN_free(M);

    return cipher;
}

int RSA_dec(U8 *dec_msg, const BIGNUM *priv, const BIGNUM *pub_N, const U8 *cipher){
    BIGNUM *C = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *d = BN_new();
    BN_hex2bn(&C, cipher);

    // Decrypt: M = C^d mod N
    BN_copy(d, priv);
    BN_mod_exp(M, C, d, pub_N, BN_CTX_new());

    // Get the length of the decrypted message
    int msg_len = BN_num_bytes(M);

    // Convert decrypted message to string
    BN_bn2bin(M, dec_msg);

    // Free resources
    BN_free(C);
    BN_free(M);
    BN_free(d);

    return msg_len;
}

int main() {
	U8 *msg = "hello";
	BIGNUM * e = BN_new();
	BIGNUM * d = BN_new();
	BIGNUM * N = BN_new();
	RSA_setup(e, N, d);
	U8 * cipher = RSA_enc(msg, e, N);
	printf("Cipher text : %s\n", cipher);
	U8 dec_msg[1024] = { 0 };
	int dec_len = RSA_dec(dec_msg, d, N, cipher);
	printf("dec : %s\n", dec_msg);

	BN_free(e);
	BN_free(N);
	BN_free(d);
	return 0;
}