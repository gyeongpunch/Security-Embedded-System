#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>
void BN_scanf(BIGNUM *input)
{
	int x;
	scanf("%d", &x);
	BN_set_word(input, x);
}
void BN_printf(const BIGNUM *input)
{
	char *c = BN_bn2dec(input);
	printf("%s ", c);
	free(c);
}
BIGNUM* BN_Square_Multi(BIGNUM *x, BIGNUM *a, BIGNUM *n)
{
	/* your code here */
	BIGNUM *result = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *z = BN_new();
	BN_CTX *bn_ctx = BN_CTX_new();
    BN_one(z); // z = 1

    BN_mod(result, x, n, BN_CTX_new());

    for (int i = BN_num_bits(a) - 2; i >= 0; i--) {
        // Square
        BN_mod_mul(result, result, result, n, bn_ctx);

        if (BN_is_bit_set(a, i)) { // i번째 비트가 1이면
            BN_mod_mul(result, result, x, n, bn_ctx); // result = (result * x) % n
        }
    }

    BN_free(temp);
    BN_free(z);

    return result;
	
}
int main(int argc, char* argv[]) {
	BIGNUM *x, *a, *n, *result;
	x = BN_new(); a = BN_new(); n = BN_new();
	printf("FAST Exponentiation (Square and Multiply)\n");
	printf("////////////  x^(a) mod n = ?   /////////////////\n");
	printf("x:"); BN_scanf(x);
	printf("a:"); BN_scanf(a);
	printf("n:"); BN_scanf(n);
	result = BN_Square_Multi(x, a, n);
	printf("result = "); BN_printf(result); printf("\n");
	BN_free(x); BN_free(a); BN_free(n); BN_free(result);
	return 0;
}
