#include <stdio.h>
#include "lib.h"

char s_key[] = "1010101010111011000010010001100000100111001101101100110011011101";          //Enter your s_key here
char plain_text[] = "0001001000110100010101101010101111001101000100110010010100110110";     //Enter your plaintext here 

char k56[57];
char rk[29], lk[29];
char key[16][57];
char key48[16][49];
char plaintext_ip[64];
char l[33], r[33];
char exr[48];
char inputS[49];                        // result of expR XOR K
char inputP[33];                        // result of s_box
char outputP[33];
char mixer[33];
char f[65];
char cipher[65];

char cipherip[65];
char decrypt[65];

int main() {
    // generate array of key from secret key
    printf("Plain text: %s\n", plain_text);
    printf("Secret key: %s\n", s_key);
    printf("\n------Generate key------\n");
    keyGen(s_key, k56);
    printf("cipher key 56 bit: %s\n", k56);
    dvkey(k56, lk, rk);
    shiftkey(key, lk, rk, key48);
    printf("Key 48 bit:\n");
    for (int i = 0; i < 16; i++) {
        printf("K[%d]: %s\n", i + 1,key48[i]);
    }

    printf("\n------ENCRYPT------\n");
    plain_ip(plain_text, plaintext_ip);
    dvPlainIP(plaintext_ip, l, r);

    // DES cipher
    for (int i = 0; i < 16; i++)
    {
        expansionR(r, exr);
        XOR48(exr, key48[i], inputS);
        s_box(inputS, inputP);
        straightR(inputP, outputP);
        XOR32(outputP, l, mixer);
        if (i != 15)
        {
            strcpy(l, r);
            strcpy(r, mixer);
        }
        else
        {
            strcpy(l, mixer);
        }
        printf("L[%d]: %s\nR[%d]: %s\n\n", i +1, l, i + 1, r);
    }
    
    strncpy(f, l, 32);
    strncpy(f + 32, r, 32);
    f[65] = 0;

    finalPer(f, cipher);
    printf("Cipher: %s\n", cipher);

//decrypt
    printf("\n------DECRYPT------\n");
    plain_ip(cipher, cipherip);
    dvPlainIP(cipherip, l, r);

    for (int i = 15; i >= 0; i--) {
        expansionR(r, exr);
        XOR48(exr, key48[i], inputS);
        s_box(inputS, inputP);
        straightR(inputP, outputP);
        XOR32(outputP, l, mixer);
        if (i)
        {
            strcpy(l, r);
            strcpy(r, mixer);
        }
        else
        {
            strcpy(l, mixer);
        }
        printf("L[%d]: %s\nR[%d]: %s\n\n", i + 1, l, i + 1, r);
    }

    strncpy(f, l, 32);
    strncpy(f + 32, r, 32);
    f[65] = 0;

    finalPer(f, decrypt);
    printf("Decrypt: %s\n", decrypt);

    printf("\n------Check decrypt output------\n");
    if (strncmp(plain_text, decrypt, 64) == 0) {
        printf("Correct!\n");
    }
    else    
        printf("Incorrect\n");

    return 0;
}