#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "include/api.h"
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>


#define NONCE_LENGTH 16
#define PLAIN_LENGTH 8
#define CIPHER_LENGTH 8

#define HEXNUM_SIZE 3
#define DATA_LENGTH 16

#define ID_ECU "0000000000000001"
#define N_ECU 2

uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
uint8_t sk[pqcrystals_kyber512_SECRETKEYBYTES];

int use_encryption = 1;


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        handleErrors();
    }
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        handleErrors();
    }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        handleErrors();
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        handleErrors();
    }
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        handleErrors();
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


void intToHex(char dest[HEXNUM_SIZE], int num) {
    int rem, quo;
    int i=0, j, temp;
    char tempDest[HEXNUM_SIZE];

    //Clean the destination
    for(int i = 0; i < HEXNUM_SIZE; i++) {
        tempDest[i] = '\0';
        dest[i] = '\0';
    }
    
    if (num == 0) {
        tempDest[i] = 48;
        i++;
    } else {
        
        quo = num;
        while(quo != 0) {
            temp = quo % 16;
            
            //Calcola valore ASCII corrispondente
            if( temp < 10) {
                temp = temp + 48;
            } else {
                temp = temp + 55;
            }

            tempDest[i]= temp;
            i++;
            quo = quo / 16;
        }
    }

    int n = i;

    for (j = 0; j < n; j++) {
        dest[j] = tempDest[i-1];
        i--;
    }


    //dest = strrev(dest);
    // dest[i] = 0;
}

int hexToInt(char* num) {
    int len, acc, tempNum, exp;

    len = strlen(num);
    acc = 0;
    exp = len - 1;

    for (int i = 0; i < len; i++) {
        if (isdigit(num[i])) {
            tempNum = num[i] - 48;
        } else {
            tempNum = num[i] - 55;
        }
        acc += tempNum * pow(16, exp);
        exp--;
    }

    return acc;
}


int receiveKey() {
    char buffer[50];
    char tempID[DATA_LENGTH];
    int pubKeyLen = pqcrystals_kyber512_PUBLICKEYBYTES * 2;
    char tempPubKey[pubKeyLen];


    FILE* fp = popen("../can-utils-2023.03/candump -n 101 vcan0", "r");

    //Estraggo l'ID
    //TODO: toglilo da qua e mettilo nel main come listener
    fgets(buffer, 50, fp);
    int j = 0;
    for(int i = 0; i < DATA_LENGTH; i+=2) {
        tempID[i] = buffer[20 + j];
        tempID[i+1] = buffer[20 + j +1];
        j+=3;
    }

    int offset = 0;
    for (int i = 0; i < 100; i++) {
        printf("I: %d\n", i);
        fgets(buffer, 50, fp);

        printf("BUF: %s\n", buffer);

        j = 0;
        for(int k = 0; k < DATA_LENGTH; k+=2) {
            tempPubKey[offset + k] = buffer[20 + j];
            tempPubKey[offset + k+1] = buffer[20 + j + 1];
            j+=3;
        }
        offset += DATA_LENGTH;
    }

    pclose(fp);

    printf("Received:");
    for (int i = 0; i < pubKeyLen; i+=2) {
        printf(" %c%c", tempPubKey[i], tempPubKey[i+1]);        
    }
    printf("\n");

    int tempIndex = 0;
    char temp[3];
    temp[2] = '\0';
    for (int i = 0; i < pqcrystals_kyber512_PUBLICKEYBYTES; i++) {
        temp[0] = tempPubKey[tempIndex];
        temp[1] = tempPubKey[tempIndex + 1];
        pk[i] = hexToInt(temp);
        tempIndex += 2;
    }

    return 0;
}

void sendCipherText(uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES]) {
    char buf[DATA_LENGTH + 1];
    char hexNum[HEXNUM_SIZE];

    int tempBufSize = pqcrystals_kyber512_CIPHERTEXTBYTES * 2;
    char tempBuf[tempBufSize];

    char* cmd;
    char* commandName = "../can-utils-2023.03/cansend vcan0 122#";

    int len = strlen(commandName) + 9;
    cmd = malloc(len * sizeof(char));

    strcpy(cmd, commandName);

    //Il primo messaggio del protocollo sarà l'ID del sender
    strcat(cmd, ID_ECU);
    printf("COMMAND: %s\n", cmd);
    system(cmd);
    
    int j = 0;
    for (int i = 0; i < pqcrystals_kyber512_CIPHERTEXTBYTES; i++) {
        intToHex(hexNum, ct[i]);
        
        if (ct[i] < 16) {
            tempBuf[j] = '0';
            tempBuf[j+1] = hexNum[0];
        } else {
            tempBuf[j] = hexNum[0];
            tempBuf[j+1] = hexNum[1];
        }
        
        j+=2;
    }

    for (int i = 0; i < tempBufSize; i += DATA_LENGTH) {
        for (j = 0; j < DATA_LENGTH; j++) {
            buf[j] = tempBuf[i + j];
        }
        buf[DATA_LENGTH] = '\0';
        
        strcpy(cmd, commandName);
        strcat(cmd, buf);
        printf("CMD: %s\n", cmd);
        system(cmd);
        printf("FINITO\n");
    }
}

void sendkey(uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES]) {
    char buf[DATA_LENGTH + 1];
    char hexNum[HEXNUM_SIZE];
    
    int tempBufSize = pqcrystals_kyber512_PUBLICKEYBYTES * 2;
    char tempBuf[tempBufSize];
    char* cmd;
    char* commandName = "../can-utils-2023.03/cansend vcan0 111#";
    int len = strlen(commandName) + DATA_LENGTH + 1;
    cmd = malloc(len * sizeof(char));
    strcpy(cmd, commandName);

    //Il primo messaggio del protocollo sarà l'ID del sender
    strcat(cmd, ID_ECU);
    system(cmd);

    int j = 0;
    int i = 0;
    for (i = 0; i < pqcrystals_kyber512_PUBLICKEYBYTES; i++) {

        intToHex(hexNum, pk[i]);
        
        if (pk[i] < 16) {
            tempBuf[j] = '0';
            tempBuf[j+1] = hexNum[0];
        } else {
            tempBuf[j] = hexNum[0];
            tempBuf[j+1] = hexNum[1];
        }
        
        j+=2;
    }

    i = 0;
    for (i = 0; i < tempBufSize; i += DATA_LENGTH) {
        for (j = 0; j < DATA_LENGTH; j++) {
            buf[j] = tempBuf[i + j];
        }

        buf[DATA_LENGTH] = '\0';
        
        strcpy(cmd, commandName);
        strcat(cmd, buf);
        printf("CMD: %s\n", cmd);
        system(cmd);
        //printf("FINITO\n");
    }
}

void receiveCangen(uint8_t ss[pqcrystals_kyber512_ref_BYTES]) {
    
    uint8_t nonce[NONCE_LENGTH];
    uint8_t payload[PLAIN_LENGTH];
    uint8_t payloadEncrypted[CIPHER_LENGTH];
    char tempPayload[DATA_LENGTH];
    char buffer[50];
    char hexNum[HEXNUM_SIZE];

    hexNum[HEXNUM_SIZE] = '\0';

    FILE* fp = popen("../can-utils-2023.03/candump vcan0", "r");

    int nonceSeed = 0;

    for (int i = 0; i < pqcrystals_kyber512_BYTES; i++) {
        nonceSeed += ss[i];
    }

    printf("NONCESEED: %d\n", nonceSeed);

    srand(nonceSeed);

    for (int i = 0; i < NONCE_LENGTH; i++) {
        nonce[i] = rand() % 256;
    }

    fgets(buffer, 50, fp);
    fgets(buffer, 50, fp);
    fgets(buffer, 50, fp);

    int i, j, n, n_messages;
    i = 0;
    j = 0;
    while(!isspace(buffer[20 + i])) {
        tempPayload[j] = buffer[20 + i];
        tempPayload[j+1] = buffer[20 + i+1];
        j+=2;
        i+=3;
    }
    tempPayload[j] = '\0';

       printf("TEMP: %s\n", tempPayload);

    n_messages = hexToInt(tempPayload);
    printf("N MESSAGES: %d\n", n_messages);

    
    int offset;

    for (n = 0; n < n_messages; n++) {
        fgets(buffer, 50, fp);
        i = 0;
        j = 0;
        // Leggo il payload del messaggio a coppie
        while(!isspace(buffer[20 + i])) {
            tempPayload[j] = buffer[20 + i];
            tempPayload[j+1] = buffer[20 + i+1];
            j+=2;
            i+=3;
        }
        tempPayload[j] = '\0';
        printf("TEMP_PAYLOAD: %s\n", tempPayload);
        
        i = 0;
        int len = strlen(tempPayload);
        for(int k = 0; k < len; k+=2) {
            hexNum[0] = tempPayload[k];
            hexNum[1] = tempPayload[k+1];
            printf("\t\tHEXNUM: %s\n", hexNum);
            payloadEncrypted[i] = hexToInt(hexNum);
            i++;
        }

        for (int j = i; j < CIPHER_LENGTH; j++) {
            payloadEncrypted[j] = '\0';
        }

        printf("\t\tLunghezza: %d\t%d\n\n", len, i);
        len = i;
        if (len != 0) {
            decrypt(payloadEncrypted, i, ss, nonce, payload);
        }

        printf("DECIFRATO:");
        for(int i = 0; i < len; i++) {
            printf(" %d", payload[i]);
        }
        printf("\n\n\n");
    }
    printf("FINE\n");
    
}

int cangen(uint8_t ss[pqcrystals_kyber512_BYTES]) {
    char* cmd;
    char* commandName = "../can-utils-2023.03/cangen vcan0 -n 1 -D ";
    

    int len = strlen(commandName) + 30;
    cmd = malloc(len * sizeof(char));

    uint8_t nonce[NONCE_LENGTH];

    // if (isSharedKeyEmpty(id)) {
    //     printf("EMPTY KEY\n");
    //     return 0;
    // }
    // printf("NOT EMPTY KEY\n");

    // Buffer per pulire la pipe
    char temp[50];

    int nonceSeed = 0;

    for (int i = 0; i < pqcrystals_kyber512_BYTES; i++) {
        nonceSeed += ss[i];
    }

    srand(nonceSeed);

    for (int i = 0; i < NONCE_LENGTH; i++) {
        nonce[i] = rand() % 256;
    }

    printf("SEED: %d\n", nonceSeed);

    time_t t;
    srand(time(&t));

    int n_messages = rand() % 255 + 1;

    char hexNum[HEXNUM_SIZE];
    hexNum[HEXNUM_SIZE -1] = '\0';

    // Invio ID e numero di messaggi
    char* idToSend = "../can-utils-2023.03/cansend vcan0 00B#";
    int sendLen = strlen(idToSend);
    char* preCmd = malloc( (sendLen + 20) * sizeof(char));
    strcpy(preCmd, idToSend);
    strcat(preCmd, ID_ECU);
    system(preCmd);

    strcpy(preCmd, idToSend);
    intToHex(hexNum, n_messages);
    strcat(preCmd, hexNum);
    system(preCmd);

    free(preCmd);

    uint8_t payload[PLAIN_LENGTH];
    uint8_t payloadEncrypted[CIPHER_LENGTH];
    
    

    char* temp_length = malloc(5 * sizeof(char));

    for (int i = 0; i < n_messages; i++) {
        int length = rand() % 9; // La lunghezza massima è 8 byte

        printf("PAYLOAD:");
        for (int j = 0; j < length; j++) {
            payload[j] = rand() % 256;
            printf(" %d", payload[j]);
        }
        printf("\n\n");

        if (use_encryption && length != 0) {
            commandName = "../can-utils-2023.03/cangen vcan0 -n 1 -D ";
// Tempo iniziale
            encrypt(payload, length, ss, nonce, payloadEncrypted);

            printf("PAYLOAD CIFRATO:");
        for (int j = 0; j < length; j++) {
            printf(" %d", payloadEncrypted[j]);
        }
        printf("\n\n");

            char buffer[DATA_LENGTH + 1];
            
            int k = 0;
            for (int j = 0; j < length; j++) {
                
                intToHex(hexNum, payloadEncrypted[j]);
                
                if (payloadEncrypted[j] <= 16) {
                    buffer[k] = '0';
                    buffer[k+1] = hexNum[0];
                } else {
                    buffer[k] = hexNum[0];
                    buffer[k+1] = hexNum[1];
                }

                k+=2;
            }

            buffer[k] = '\0';
            char final_length = length + 48; //integer to ascii
            

            strcpy(temp_length, " -L ");
            int temp_len = strlen(temp_length);
            temp_length[temp_len] = final_length;
            temp_length[temp_len + 1] = '\0';

            strcpy(cmd, commandName);
            strcat(cmd, buffer);
            strcat(cmd, temp_length);
            
        
        } else {
            commandName = "../can-utils-2023.03/cangen vcan0 -n 1 -L 0";
            strcpy(cmd, commandName);
        }
        printf("COMANDO: %s---\n", cmd);
        system(cmd);
// Tempo finale

    }

    free(temp_length);
    free(cmd);
    return 1;

}


int main() {
    uint8_t pk_local[pqcrystals_kyber512_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_kyber512_SECRETKEYBYTES];
    uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES];
    uint8_t ss[pqcrystals_kyber512_BYTES];
    char buffer[50];

    // pqcrystals_kyber512_ref_keypair(pk_local, sk);

    receiveKey(); 

    printf("CHIAVE RICEVUTA:");
    for (int i = 0; i < pqcrystals_kyber512_PUBLICKEYBYTES; i++) {
        printf(" %u", pk[i]);
    }
    printf("\n");

    pqcrystals_kyber512_ref_enc(ct, ss, pk);

    sendCipherText(ct);

    printf("SHARED originale:");
    for (int i = 0; i < pqcrystals_kyber512_BYTES; i++) {
        printf(" %u", ss[i]);
    }
    printf("\n");

    char* cmd;
    char* commandName = "../can-utils-2023.03/cansend vcan0 00A#";

    int len = strlen(commandName) + 9;
    cmd = malloc(len * sizeof(char));

    strcpy(cmd, commandName);

    //receiveCangen(ss);
    printf("PRIMA CANGEN\n");
    cangen(ss);

    //Il primo messaggio del protocollo sarà l'ID del sender
    // strcat(cmd, ID_ECU);
    // system(cmd);

    return 0;

}