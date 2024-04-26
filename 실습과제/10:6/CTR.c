#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>
typedef unsigned char U8;
typedef unsigned int U32;
#define BYTES 16
#define BITS 128

int Gen(U8 *key) {
    if (key == NULL) return 0;
    RAND_bytes(key, BYTES);
    return 1;
}

// U8 *key       : key for AES_set_encrypt_key
// const U8 *msg : message to be encrypted
// U8 *ctr       : ciphertext (output)
// returns length of ciphertext
int ctrEnc(U8 *key, const U8* msg, U8 *ctr) {
    int i, j, msg_len = strlen((const char*)msg), mb_len = ((msg_len / BYTES) + 1) * BYTES, bottom = BYTES - 1;
    U8 IV[BYTES] = {0}, PRF[BYTES], msg_block[mb_len];

    // AES key setting
    AES_KEY enckey;
    AES_set_encrypt_key(key, BITS, &enckey);

    // Copy IV to ctr
    memcpy(ctr, IV, BYTES);

    // Copy msg to msg_block
    memcpy(msg_block, msg, msg_len);

    // Calculate padding
    int pad = mb_len - msg_len;

    // Set padding to last msg_block
    for (j = 0; j < pad; j++)
        msg_block[msg_len + j] = pad;

    // Print padded msg
    printf("m_t \t\t: ");
    for (j = 0; j < BYTES; j++)
        printf("%02X", msg_block[mb_len - BYTES + j]);
    printf("\n");

    for (i = 0; i < msg_len / BYTES + 1; i++) {
        // IV++
        j = bottom;
        do { IV[j] += 1; } while (IV[j--] == 0 && j != 0);

        // PRF(IV) = PRF
        AES_encrypt(IV, PRF, &enckey);

        // Set ctr = PRF xor msg_block
        for (j = 0; j < BYTES; j++)
            ctr[j] = PRF[j] ^ msg_block[i * BYTES + j];
    }
    return (i + 1) * BYTES;
}

int ctrDec(U8 *key, const U8 *ctr, int ct_len, U8* dec_msg) {
    U8 IV[BYTES], PRF[BYTES], msg_block[ct_len];
    int i, j, bottom = BYTES - 1;
    AES_KEY enckey;

    // AES key setting
    AES_set_encrypt_key(key, BITS, &enckey);

    // Copy IV from ctr
    memcpy(IV, ctr, BYTES);

    for (i = 0; i < ct_len / BYTES; i++) {
        // IV++
        j = bottom;
        do { IV[j] += 1; } while (IV[j--] == 0 && j != 0);

        // PRF = enc(IV)
        AES_encrypt(IV, PRF, &enckey);

        // dec_msg = ctr xor PRF
        for (j = 0; j < BYTES; j++)
            dec_msg[i * BYTES + j] = ctr[i * BYTES + j] ^ PRF[j];
    }
    U8 pad = dec_msg[ct_len - 1];
    if (pad <= 0 || pad > BYTES) return 0;

    // Remove padding
    for (j = 0; j < pad; j++)
        dec_msg[ct_len - 1 - j] = 0;

    printf("Dec m_t \t: ");
    for (j = 0; j < ct_len - pad; j++)
        printf("%c", dec_msg[j]);
    printf("\n");
    return ct_len - pad;
}

int main(int argc, char* argv[]) {
    RAND_status(); // random seed

    U8 key[BYTES];
    U8 m[] = "If F is a pseudorandom function, then CTR mode is CPA-secure";

    // set ctr : ciphertext
    int ctr_len = (strlen((char*)m) % BYTES == 0) ? BYTES * (strlen((char*)m) / BYTES + 1) : BYTES * (strlen((char*)m) / BYTES + 2);
    U8 *ctr = (U8 *)calloc(ctr_len, sizeof(U8));

    Gen(key);
    ctr_len = ctrEnc(key, m, ctr);
    // Enc done

    U8 *dec_msg = (U8 *)calloc(ctr_len, sizeof(U8));
    int m_len = ctrDec(key, ctr, ctr_len, dec_msg);
    // Dec done

    // print Enc
    printf("Enc \t\t: ");
    for (int i = 0; i < ctr_len; i++)
        printf("%02X", ctr[i]);
    printf("\n");

    // print Dec
    if (m_len > 0)
        printf("Decryption \t: %s\n", dec_msg);
    else
        printf("Error!!! %d\n", m_len);

    free(ctr);
    free(dec_msg);
    return 0;
}
