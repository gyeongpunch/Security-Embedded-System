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
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
}BN_group;

BN_group BN_group_new(const BIGNUM *p, const BIGNUM *q, const BIGNUM *g) {
	BN_group group;
	group.p = BN_new(); group.q = BN_new(); group.g = BN_new();
	BN_copy(group.p, p);
	BN_copy(group.q, q);
	BN_copy(group.g, g);
	return group;
}
void BN_group_free(BN_group *group)
{
	BN_free(group->p);
	BN_free(group->q);
	BN_free(group->g);
}
/*
	p = tq + 1
	p, q : prime
	g : generator
*/
BN_group Group_selection() {
	
	BN_group group;
	
	BIGNUM *p = BN_new(); 
	BIGNUM *q = BN_new();
	BIGNUM *g = BN_new();
	BIGNUM *t = BN_new();
	
	BN_CTX *bn_ctx = BN_CTX_new();
	
	while(1){
		// Generate prim q

		
		// p = tq + 1
		
		
		// p is prime?
		
		
		// get generator g
		
		
		// cmp with 1
		
		
		// make group
		
		break;
	}
	// free
	
	return group;
}

int main(int argc, char* argv[]) {
	BN_group group;
	group = Group_selection();

	printf("\n p : "); BN_printf(group.p);
	printf("\n q : "); BN_printf(group.q);
	printf("\n g : "); BN_printf(group.g);
	
	BIGNUM *tmp = BN_new();
	BN_CTX *bn_ctx = BN_CTX_new();
	
	BN_mod_exp(tmp,group.g,group.q,group.p,bn_ctx);
	printf("\n check : "); BN_printf(tmp);
	BN_free(tmp);
	BN_CTX_free(bn_ctx);

	printf("\np : %d bit",BN_num_bits(group.p));
	printf("\nq : %d bit",BN_num_bits(group.q));

	
	BN_group_free(&group);
	printf("\n");
	return 0;
}
