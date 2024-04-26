#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>

void BN_scanf(BIGNUM *input) {
	int x;
	scanf("%d", &x);
	BN_set_word(input, x);
}

void BN_printf(const BIGNUM *input) {
	char *c = BN_bn2dec(input);
	printf("%s ", c);
}
typedef struct {
	BIGNUM *d;
	BIGNUM *x;
	BIGNUM *y;
}BN_dxy;

BN_dxy BN_dxy_new(const BIGNUM *d, const BIGNUM *x, const BIGNUM *y) {
	BN_dxy dxy;
	dxy.d = BN_new(); dxy.x = BN_new(); dxy.y = BN_new();
	if (d == NULL)
		return dxy;
	BN_copy(dxy.d, d);
	BN_copy(dxy.x, x);
	BN_copy(dxy.y, y);
	return dxy;
}
void BN_dxy_copy(BN_dxy * dxy, BIGNUM *d, BIGNUM *x, BIGNUM *y)
{
	BN_copy(dxy->d, d);
	BN_copy(dxy->x, x);
	BN_copy(dxy->y, y);
}
void BN_dxy_free(BN_dxy * dxy)
{
	BN_free(dxy->d);
	BN_free(dxy->x);
	BN_free(dxy->y);
}
BN_dxy BN_Ext_Euclid(BIGNUM* a, BIGNUM* b) {
	BN_dxy dxy;
	BN_CTX *bn_ctx = BN_CTX_new();
	
	if (BN_is_zero(b)) {
		dxy = BN_dxy_new(a, BN_value_one(), b);
	}
	else {
		/* your code here */
		BIGNUM *div = BN_new();
		BIGNUM *rem = BN_new();
		BIGNUM *temp = BN_new();
		
		BN_div(div, rem, a, b, bn_ctx);
        BN_dxy result = BN_Ext_Euclid(b, rem);

		// temp에 [a/b] * y' 넣자
        BN_mul(temp, div, result.y, bn_ctx); 
        // temp = x' - temp = x' - [a/b] * y'
        BN_sub(temp, result.x, temp);
		
		dxy = BN_dxy_new(result.d, result.y, temp);
		
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

int main(int argc, char* argv[]) {
	BIGNUM *a, *b;
	BN_dxy dxy;
	a = BN_new(); b = BN_new();
	printf("a: "); BN_scanf(a);
	printf("b: "); BN_scanf(b);
	printf("result : \n");
	dxy = BN_Ext_Euclid(a, b);
	BN_printf(dxy.d); BN_printf(dxy.x); BN_printf(dxy.y);
	BN_dxy_free(&dxy);
	printf("\n");
	return 0;
}
