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
typedef struct{
	union {
		BIGNUM *p;
		BIGNUM *d;
	};
	union {
		BIGNUM *g;
		BIGNUM *x;
	};
	BIGNUM *y;

}BN_dxy;
void BN_scanf(BIGNUM *input){
	int x;
	scanf("%d", &x);
	BN_set_word(input, x);
}
void BN_printf(const BIGNUM *input){
	U8 *c = BN_bn2dec(input);
	printf("%s", c);
}
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
void BN_dxy_copy(BN_dxy * dxy, BIGNUM *d, BIGNUM *x, BIGNUM *y){
	BN_copy(dxy->d, d);
	BN_copy(dxy->x, x);
	BN_copy(dxy->y, y);
}
void BN_dxy_free(BN_dxy * dxy){
	BN_free(dxy->d);
	BN_free(dxy->x);
	BN_free(dxy->y);
}
BN_dxy BN_Ext_Euclid(BIGNUM* a, BIGNUM* b) {
	BN_dxy dxy;
	
	if (BN_is_zero(b)) {
		dxy = BN_dxy_new(a, BN_value_one(), b);
	}
	else {
		/* your code here */
		BN_CTX *bn_ctx = BN_CTX_new();
		BIGNUM *div = BN_new();
		BIGNUM *rem = BN_new();
		BIGNUM *temp = BN_new();
		
		BN_div(div, rem, a, b, bn_ctx);
        dxy = BN_Ext_Euclid(b, rem);

		// temp에 [a/b] * y' 넣자
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
BIGNUM* BN_Square_Multi(BIGNUM *x, BIGNUM *a, BIGNUM *n){
	/*code*/
	BIGNUM *z = BN_new();
	BN_CTX *bn_ctx = BN_CTX_new();
    BN_one(z); // z = 1

    for (int i = BN_num_bits(a) - 1; i >= 0; i--) {
        // Square
        BN_mod_mul(z, z, z, n, bn_ctx); // z = z^2 mod n

        if (BN_is_bit_set(a, i)) { // i번째 비트가 1이면
            BN_mod_mul(z, z, x, n, bn_ctx); // z = (z * x) mod n
        }
    }

    return z;
}

void Find_prime_subgroup_generator(BIGNUM *g, BIGNUM *p) {
		
	BIGNUM *q = BN_new();
	BIGNUM *t = BN_new();
	
	BN_CTX *bn_ctx = BN_CTX_new();
	
	while(1){
		// Generate prim q
		BN_generate_prime_ex(q,224,0,NULL,NULL,NULL);
		
		// p = tq + 1
		BN_rand(t,800,BN_RAND_TOP_ANY,BN_RAND_BOTTOM_ANY);
		BN_mul(p,t,q,bn_ctx);
		BN_add(p,p,BN_value_one());

		
		// p is prime?
		if(BN_num_bits(p) != 1024 || BN_is_prime_fasttest_ex(p,2,bn_ctx,0,NULL) == 0){
			continue;
		}
		
		// get generator g
		BN_rand_range(g,p);
		BN_mod_exp(g,g,t,p,bn_ctx);
		// cmp with 1
		if(BN_cmp(g,BN_value_one()) == 0){
			continue;
		}
		break;
	}
	// free
	BN_free(q);
	BN_free(t);
	BN_CTX_free(bn_ctx);
	
}


void Elgamal_setup(BN_dxy *pub, BIGNUM *priv) {
	if (pub->p == NULL) pub->p = BN_new();
	if (pub->g == NULL) pub->g = BN_new();
	if (pub->y == NULL) pub->y = BN_new();
	Find_prime_subgroup_generator(pub->g, pub->p); // find generator g
	BN_rand_range(priv, pub->p); // x <- Z_p
	pub->y = BN_Square_Multi(pub->g, priv, pub->p); // y = g^x mod p
	printf("Complete the select of prime\n");
	printf("Complete the select of generator\n");
}
U8 ** Elgamal_enc(const BN_dxy *pub, U8* msg, int msg_len){
	// c1 = cipher[0] , c2 = cipher[1]
	U8** cipher = (U8**)malloc(sizeof(U8*) * 2);
	BIGNUM* bn_msg = BN_new();
	BIGNUM* r = BN_new();
	BN_bin2bn(msg, msg_len, bn_msg);
	BN_rand_range(r, pub->p);
	/*code*/
	
	// c1 = g^r mod p
    BIGNUM *c1 = BN_Square_Multi(pub->g, r, pub->p);
    cipher[0] = BN_bn2hex(c1);

    // c2 = (m * y^r) mod p
    BIGNUM *temp1 = BN_Square_Multi(pub->y, r, pub->p);
    BIGNUM *temp2 = BN_new();
    BN_mod_mul(temp2, bn_msg, temp1, pub->p, BN_CTX_new());
    cipher[1] = BN_bn2hex(temp2);

    BN_free(c1);
    BN_free(temp1);
    BN_free(temp2);
    BN_free(bn_msg);
    BN_free(r);
	
	return cipher;
}
U8* Elgamal_dec(int *msg_len, U8 ** cipher, BIGNUM *priv, const BN_dxy *pub){
	/*code*/
	BIGNUM *c1 = BN_new();
    BIGNUM *c2 = BN_new();
    BN_hex2bn(&c1, cipher[0]);
    BN_hex2bn(&c2, cipher[1]);
	
	// s = c1^x mod p
    BIGNUM *s = BN_Square_Multi(c1, priv, pub->p);

    // s_inv = s^(-1) mod p
    BIGNUM *s_inv = BN_mod_inverse(NULL, s, pub->p, BN_CTX_new());

    // m = (c2 * s_inv) mod p
    BIGNUM *m = BN_new();
    BN_mod_mul(m, c2, s_inv, pub->p, BN_CTX_new());

    *msg_len = BN_num_bytes(m);
    U8 *dec_msg = (U8*)malloc(*msg_len);
    BN_bn2bin(m, dec_msg);

    BN_free(c1);
    BN_free(c2);
    BN_free(s);
    BN_free(s_inv);
    BN_free(m);

    return dec_msg;
}

int main() {
	BN_dxy pub = { 0 };
	BIGNUM *priv = BN_new();
	Elgamal_setup(&pub, priv);
	U8 msg[] = "hello, world";
	U8 **cipher = Elgamal_enc(&pub, msg, (int)strlen(msg));
	printf("p\t: %s\n", BN_bn2hex(pub.p));
	printf("g\t: %s\n", BN_bn2hex(pub.g));
	printf("c1\t: %s\n", cipher[0]);
	printf("c2\t: %s\n", cipher[1]);
	int msg_len;
	U8 *dec_msg = Elgamal_dec(&msg_len, cipher, priv, &pub);
	printf("dec\t: %s\n", dec_msg);
	printf("msg_len\t: %d\n", msg_len);
	OPENSSL_free(cipher[0]);
	OPENSSL_free(cipher[1]);
	free(cipher);
	free(dec_msg);
	BN_dxy_free(&pub);

	return 0;
}