#include <stdio.h>
#include <string.h>

int PC1[] = {57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4};

int PC2[] = {14, 17, 11, 24, 1, 5,
             3, 28, 15, 6, 21, 10,
             23, 19, 12, 4, 26, 8,
             16, 7, 27, 20, 13, 2,
             41, 52, 31, 37, 47, 55,
             30, 40, 51, 45, 33, 48,
             44, 49, 39, 56, 34, 53,
             46, 42, 50, 36, 29, 32};

int IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7};

int EP_box[] = {32, 1, 2, 3, 4, 5,
               4, 5, 6, 7, 8, 9,
               8, 9, 10, 11, 12, 13,
               12, 13, 14, 15, 16, 17,
               16, 17, 18, 19, 20, 21,
               20, 21, 22, 23, 24, 25,
               24, 25, 26, 27, 28, 29,
               28, 29, 30, 31, 32, 1};

int SP_box[] = {16, 7, 20, 21,
                29, 12, 28, 17,
                1, 15, 23, 26,
                5, 18, 31, 10,
                2, 8, 24, 14,
                32, 27, 3, 9,
                19, 13, 30, 6,
                22, 11, 4, 25};

int S1[4][16] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13};

int S2[4][16] = {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9};

int S3[4][16] = {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12};

int S4[4][16] = {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14};

int S5[4][16] = {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3};

int S6[4][16] = {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13};

int S7[4][16] = {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12};

int S8[4][16] = {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11};

int Final_P[] = {40, 8, 48, 16, 56, 24, 64, 32,
                 39, 7, 47, 15, 55, 23, 63, 31,
                 38, 6, 46, 14, 54, 22, 62, 30,
                 37, 5, 45, 13, 53, 21, 61, 29,
                 36, 4, 44, 12, 52, 20, 60, 28,
                 35, 3, 43, 11, 51, 19, 59, 27,
                 34, 2, 42, 10, 50, 18, 58, 26,
                 33, 1, 41, 9, 49, 17, 57, 25};

void rtl(char *str, int n) {                        // rotate left
    int len = strlen(str);
    char tmp[len + 1];
    strncpy(tmp, str + n,  len - n);
    strncpy(tmp + len - n, str, n);
    tmp[len] = 0;
    strcpy(str, tmp);
}

void decimalToBinary4(int n, char *result)
{
    for (int i = 3; i >= 0; i--)
    {
        result[3 - i] = (n & (1 << i)) ? '1' : '0';
    }
    result[4] = '\0';
}

void keyGen(const char *key64, char *key56) {
    for (int i = 0; i < 56; i++) {
        key56[i] = key64[PC1[i] - 1];
    }
}

void dvkey(const char *key56, char* lkey, char *rkey) {
    strncpy(lkey, key56, 28);
    strncpy(rkey, key56 + 28, 28);
}

void shiftkey(char key[16][57], char *lk, char *rk, char key48[16][49]) {
    for(int i = 0; i < 16; i++) {
        if ((i + 1) == 1 || (i + 1) == 2 || (i + 1) == 9 || (i + 1) == 16) {
            rtl(lk, 1);
            rtl(rk, 1);
        }
        else {
            rtl(lk, 2);
            rtl(rk, 2);
        }
        strcpy(key[i], lk);
        strcpy(key[i] + 28, rk);
        key[i][56] = 0;

        for (int j = 0; j < 48; j++) {
            key48[i][j] = key[i][PC2[j] - 1];
            key48[i][48] = 0;
        }
    }
}

void plain_ip(const char *plain, char * plainip) {
    for (int i = 0; i < 64; i++) {
        plainip[i] = plain[IP[i] - 1];
    }
}

void dvPlainIP(const char *plainip, char *l, char *r) {
    strncpy(l, plainip, 32);
    strncpy(r, plainip + 32, 32);    
    l[32] = 0;
    r[32] =0;
}

void expansionR(const char* r, char *exr) {
    for(int i = 0; i < 48; i++) {
        exr[i] = r[EP_box[i] - 1];
    }
}

void XOR48(char *a, char *b, char *result) {
    for (int i = 0; i < 48; i ++) {
        if (a[i] != b[i]) 
            result[i] = '1';
        else 
            result[i] = '0';
    }
    result[48] = 0;
}

void XOR32(char *a, char *b, char *result)
{
    for (int i = 0; i < 32; i++)
    {
        if (a[i] != b[i])
            result[i] = '1';
        else
            result[i] = '0';
    }
    result[32] = 0;
}

void s_box(char *input, char *output) {
    for (int i = 0; i < 8; i++) {
        char group[7];
        strncpy(group, input + i * 6, 6);
        group[7] = 0;
        int row = (group[0] - '0') * 2 + (group[5] - '0');
        int col = (group[1] - '0') * 8 + (group[2] - '0') * 4 + (group[3] - '0') * 2  + (group[4] - '0');
        int value;
        switch (i)
        {
        case 0:
            value = S1[row][col];
            break;
        case 1:
            value = S2[row][col];
            break;
        case 2:
            value = S3[row][col];
            break;
        case 3:
            value = S4[row][col];
            break;
        case 4:
            value = S5[row][col];
            break;
        case 5:
            value = S6[row][col];
            break;
        case 6:
            value = S7[row][col];
            break;
        case 7:
            value = S8[row][col];
            break;
        default:
            break;
        }
        memset(group, 0, sizeof(group));
        decimalToBinary4(value, group);
        strncpy(output + i * 4, group, 4);
    }
}

void straightR(const char* input, char *output) {
    for (int i = 0; i < 32; i++) {
        output[i] = input[SP_box[i] - 1];
    }
}

void finalPer(const char *input, char *output) {
    for (int i = 0; i < 64; i++) {
        output[i] = input[Final_P[i] - 1];
    }
}