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

// gcd(a,b) = gcd(b,a mod b)
/*
	Euclid(a,b)
		if b = 0 return a
		else return Euclid(b, a mod b)
*/
BIGNUM* BN_Euclid(BIGNUM* a, BIGNUM* b) {
	if (BN_is_zero(b)) {
	}
	else {
	}
}

int main(int argc, char* argv[]) {
	BIGNUM *a, *b, *d;
	a = BN_new(); b = BN_new(); d = BN_new();
	printf("a: "); BN_scanf(a);
	printf("b: "); BN_scanf(b);
	printf("result : \n");
	d = BN_Euclid(a, b);
	BN_printf(d);
	printf("\n");
	return 0;
}
