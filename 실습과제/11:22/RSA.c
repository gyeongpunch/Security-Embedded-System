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

void BN_printf(const BIGNUM *input)
{
    char *c = BN_bn2dec(input);
    printf("%s ", c);
    OPENSSL_free(c); // Free the memory allocated by BN_bn2dec
}

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

BIGNUM *BN_Square_Multi(const BIGNUM *x, const BIGNUM *a, const BIGNUM *n)
{
    BIGNUM *z = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    BN_one(z); // z = 1
	int a_bitlen = BN_num_bits(a);
	
    for (int i = a_bitlen - 1; i >= 0; i--)
    {
        // Square
        BN_mod_mul(z, z, z, n, bn_ctx); // z = z^2 mod n

        if (BN_is_bit_set(a, i)){ // i번째 비트가 1이면
            BN_mod_mul(z, z, x, n, bn_ctx); // z = (z * x) mod n
        }
    }

    BN_CTX_free(bn_ctx);
    return z;
}

BN_dxy BN_Ext_Euclid(BIGNUM *a, BIGNUM *b)
{
    BN_dxy dxy;

    if (BN_is_zero(b)){
        dxy = BN_dxy_new(a, BN_value_one(), b);
		return dxy;
    }
    else{
        /* your code here */
        BN_CTX *bn_ctx = BN_CTX_new();
        BIGNUM *div = BN_new();
        BIGNUM *rem = BN_new();
        BIGNUM *temp = BN_new();

        BN_div(div, rem, a, b, bn_ctx); // div = a // b, rem = a % b
        dxy = BN_Ext_Euclid(b, rem); // (d', x', y') <- Ext_euclid(b, a mod b)

        // temp = [a/b] * y'
        BN_mul(temp, div, dxy.y, bn_ctx);
        // temp = x' - temp = x' - [a/b] * y'
        BN_sub(temp, dxy.x, temp);

        BN_dxy_copy(&dxy, dxy.d, dxy.y, temp);

        BN_free(div);
        BN_free(rem);
        BN_free(temp);
        BN_CTX_free(bn_ctx);
    }
    return dxy;
}

void RSA_setup(BIGNUM *pub_e, BIGNUM *pub_N, BIGNUM *priv)
{
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BN_dxy dxy;
    BIGNUM *N = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *order = BN_new(); // order of group
    BN_set_word(e, 3);

    while (1)
    {
        BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
        BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);

        // N = pq
        BN_mul(N, p, q, bn_ctx);

        // Calculate ord = (p-1)(q-1)
        BN_sub(p, p, BN_value_one());
        BN_sub(q, q, BN_value_one());
        BN_mul(order, p, q, bn_ctx);

        // Find private key (d)
        dxy = BN_Ext_Euclid(e, order);

        // e와 order가 서로소면 dxy.d가 1
        if (BN_is_one(dxy.d) == 1){
            break;
        }
    }
	
	
    // e, N 대입
    BN_copy(pub_e, e);
    BN_copy(pub_N, N);

    // d = priv
	BN_nnmod(priv, dxy.x, order, bn_ctx);
	
	
    printf("e\t : ");
    BN_printf(pub_e);
    printf("\nN\t : ");
    BN_printf(pub_N);
    printf("\ndxy.y\t : ");
    BN_printf(dxy.y);
    printf("\ndxy.x\t : ");
    BN_printf(dxy.x);
    printf("\ndxy.d\t : ");
    BN_printf(dxy.d);
    printf("\n\n");

    BN_free(p);
    BN_free(q);
    BN_dxy_free(&dxy);
    BN_free(N);
    BN_free(e);
    BN_free(order);
    BN_CTX_free(bn_ctx);
}

U8 *RSA_enc(const U8 *msg, BIGNUM *pub_e, BIGNUM *pub_N)
{
    BIGNUM *C = BN_new();
    BIGNUM *M = BN_new();
    BN_bin2bn(msg, strlen(msg), M);
    U8 *cipher;

    // C = M^e mod N
    C = BN_Square_Multi(M, pub_e, pub_N);

    cipher = BN_bn2hex(C);

    BN_free(C);
    BN_free(M);

    return cipher;
}

int RSA_dec(U8 *dec_msg, const BIGNUM *priv, const BIGNUM *pub_N, const U8 *cipher)
{
    BIGNUM *C = BN_new();
    BIGNUM *M = BN_new();

    // hex string -> BIGNUM
    BN_hex2bn(&C, cipher);

    // M = C^d mod N
    M = BN_Square_Multi(C, priv, pub_N);

    int msg_len = BN_num_bytes(M);
    BN_bn2bin(M, dec_msg);

    BN_free(C);
    BN_free(M);

    return msg_len;
}

int main()
{
    U8 *msg = "hello";
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *N = BN_new();
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
