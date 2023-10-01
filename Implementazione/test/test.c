#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <unistd.h>
#include <signal.h>
#include "include/api.h"
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <time.h>

#define NONCE_LENGTH 16
#define PLAIN_LENGTH 8
#define CIPHER_LENGTH 8

#define HEXNUM_SIZE 3
#define DATA_LENGTH 16

#define ID_ECU "0000000000000000"
#define N_ECU 2

uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
uint8_t sk[pqcrystals_kyber512_SECRETKEYBYTES];
uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES];
uint8_t ss[pqcrystals_kyber512_BYTES];

uint8_t publicKeys[N_ECU][pqcrystals_kyber512_PUBLICKEYBYTES];
uint8_t sharedKeys[N_ECU][pqcrystals_kyber512_BYTES];

int use_encryption = 1;


void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void intToHex(char dest[HEXNUM_SIZE], int num);
int hexToInt(char* num);
void sendkey(uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES], FILE* fp);
void sendCipherText(uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES], FILE* fp);





void sendkey(uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES], FILE* fp) {
    char buf[DATA_LENGTH + 1];
    char hexNum[HEXNUM_SIZE];
    
    int tempBufSize = pqcrystals_kyber512_PUBLICKEYBYTES * 2;
    char tempBuf[tempBufSize];
    char* cmd;
    char* commandName = "../can-utils-2023.03/cansend vcan0 111#";
    int len = strlen(commandName) + DATA_LENGTH + 1;
    cmd = malloc(len * sizeof(char));

    strcpy(cmd, commandName);

    // Buffer per pulire la pipe
    char temp[50];

    //Il primo messaggio del protocollo sarà l'ID del sender
    strcat(cmd, ID_ECU);
    system(cmd);

    // Pulisco la pipe dai messaggi inviati
    fgets(temp, 50, fp);

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
        //printf("CMD: %s\n", cmd);
        system(cmd);
        //printf("FGETS\n");

        // Pulisco la pipe dai messaggi inviati
        fgets(temp, 50, fp);
    }

    free(cmd);

}

void sendCipherText(uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES], FILE* fp) {
    char buf[DATA_LENGTH + 1];
    char hexNum[HEXNUM_SIZE];

    int tempBufSize = pqcrystals_kyber512_CIPHERTEXTBYTES * 2;
    char tempBuf[tempBufSize];

    char* cmd;
    char* commandName = "../can-utils-2023.03/cansend vcan0 122#";

    int len = strlen(commandName) + 9;
    cmd = malloc(len * sizeof(char));

    // Buffer per pulire la pipe
    char temp[50];

    strcpy(cmd, commandName);

    //Il primo messaggio del protocollo sarà l'ID del sender
    strcat(cmd, ID_ECU);
    system(cmd);

    // Pulisco la pipe dai messaggi inviati
    fgets(temp, 50, fp);
    
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

        // Pulisco la pipe dai messaggi inviati
        fgets(temp, 50, fp);
    }

    free(cmd);
}

// Inserisce nell'array publicKeys la chiave pubblica ricevuta nella posizione id
void receiveKey(FILE* fp, int id) {
    char buffer[50];
    int pubKeyLen = pqcrystals_kyber512_PUBLICKEYBYTES * 2;
    char tempPubKey[pubKeyLen];

    int j = 0;
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

    printf("Received HEX:");
    for (int i = 0; i < pubKeyLen; i+=2) {
        printf(" %c%c", tempPubKey[i], tempPubKey[i+1]);        
    }
    printf("\n");

    char temp[3];
    temp[2] = '\0';
    j = 0;
    
    for(int i = 0; i < pqcrystals_kyber512_PUBLICKEYBYTES; i++) {
        temp[0] = tempPubKey[j];
        temp[1] = tempPubKey[j +1];

        publicKeys[id][i] = hexToInt(temp);
        j+=2;
    }

    printf("Received INT:");
    for (int i = 0; i < pqcrystals_kyber512_PUBLICKEYBYTES; i++) {
        printf(" %u", publicKeys[id][i]);        
    }
    printf("\n");

}

int receiveCipherTextAndSharedSecret(FILE* fp, int id) {
    char buffer[50];  
    int cipherTextLen = pqcrystals_kyber512_CIPHERTEXTBYTES * 2;
    char tempCipherText[cipherTextLen];
    int j = 0;
    

    int offset = 0;
    for (int i = 0; i < 96; i++) {
        printf("I: %d\n", i);
        fgets(buffer, 50, fp);

        printf("BUF: %s\n", buffer);

        j = 0;
        for(int k = 0; k < DATA_LENGTH; k+=2) {
            tempCipherText[offset + k] = buffer[20 + j];
            tempCipherText[offset + k+1] = buffer[20 + j + 1];
            j+=3;
        }
        offset += DATA_LENGTH;
    }

    printf("ID ECU: %d\n", id);

    uint8_t cipherText[pqcrystals_kyber512_CIPHERTEXTBYTES];

    int tempIndex = 0;
    char temp[3];
    temp[2] = '\0';
    for (int i = 0; i < pqcrystals_kyber512_CIPHERTEXTBYTES; i++) {
        temp[0] = tempCipherText[tempIndex];
        temp[1] = tempCipherText[tempIndex + 1];
        cipherText[i] = hexToInt(temp);
        tempIndex += 2;
    }
    printf("DECAPS\n");
    pqcrystals_kyber512_ref_dec(sharedKeys[id], cipherText, sk);

    printf("SHARED KEY:");
    for (int i = 0; i < pqcrystals_kyber512_BYTES; i++) {
        printf(" %u", sharedKeys[id][i]);
    }
    printf("\n");

    return 0;
}

int isSharedKeyEmpty(int id) {
    
    for (int i = 0; i < pqcrystals_kyber512_BYTES; i++) {
        if (sharedKeys[id][i] != 0) {
            // Key is not empty
            return 0;
        }
    }
    // All bytes are 0, so the key is empty
    return 1;
}

int cangen(int id, FILE* fp) {
    char* cmd;
    char* commandName = "../can-utils-2023.03/cangen vcan0 -n 1 -D ";
    

    int len = strlen(commandName) + 30;
    cmd = malloc(len * sizeof(char));

    uint8_t nonce[NONCE_LENGTH];

    if (isSharedKeyEmpty(id)) {
        printf("EMPTY KEY\n");
        return 0;
    }
    printf("NOT EMPTY KEY\n");

    // Buffer per pulire la pipe
    char temp[50];

    int nonceSeed = 0;

    for (int i = 0; i < pqcrystals_kyber512_BYTES; i++) {
        nonceSeed += sharedKeys[id][i];
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
    // Pulisco la pipe dai messaggi inviati
    fgets(temp, 50, fp);

    strcpy(preCmd, idToSend);
    intToHex(hexNum, n_messages);
    strcat(preCmd, hexNum);
    system(preCmd);
    // Pulisco la pipe dai messaggi inviati
    fgets(temp, 50, fp);

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
            encrypt(payload, length, sharedKeys[id], nonce, payloadEncrypted);

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

        // Pulisco la pipe dai messaggi inviati
        fgets(temp, 50, fp);
    }

    free(temp_length);
    free(cmd);
    return 1;

}


void receiveCangen(FILE* fp, int id) {
    
    uint8_t nonce[NONCE_LENGTH];
    uint8_t payload[PLAIN_LENGTH];
    uint8_t payloadEncrypted[CIPHER_LENGTH];
    char tempPayload[DATA_LENGTH];
    char buffer[50];
    char hexNum[HEXNUM_SIZE];

    hexNum[HEXNUM_SIZE - 1] = '\0';

    int nonceSeed = 0;

    for (int i = 0; i < pqcrystals_kyber512_BYTES; i++) {
        nonceSeed += sharedKeys[id][i];
    }

    printf("NONCESEED: %d\n", nonceSeed);

    srand(nonceSeed);

    for (int i = 0; i < NONCE_LENGTH; i++) {
        nonce[i] = rand() % 256;
    }

    fgets(buffer, 50, fp);
// Tempo iniziale
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
        if (use_encryption && len != 0) {
            decrypt(payloadEncrypted, i, sharedKeys[id], nonce, payload);
        }
// Tempo finale
        printf("DECIFRATO:");
        for(int i = 0; i < len; i++) {
            printf(" %d", payload[i]);
        }
        printf("\n\n\n");
    }
    
}



int main(int argc, char* argv[]) {
    int test;
    
    uint8_t plainText[PLAIN_LENGTH];
    uint8_t cipherText[CIPHER_LENGTH];
    uint8_t nonce[NONCE_LENGTH];

    printf("GENERO CHIAVI\n");
    test = pqcrystals_kyber512_ref_keypair(pk, sk);

    for (int i = 0; i < N_ECU; i++) {
        for (int j = 0; j < pqcrystals_kyber512_BYTES; j++) {
            sharedKeys[i][j] = 0;
            //printf("SHARED %d %d = %u\n", i, j, sharedKeys[i][j]);
        }
    }

    // pqcrystals_kyber512_ref_enc(ct, ss, pk);
   
    // pqcrystals_kyber512_ref_dec(ss, ct, sk);
    // printf("Dopo decaps\n");


//     /* Encrypt the plaintext */
//     ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv, ciphertext);

    // Mi metto in ascolto sul bus
    FILE* fp = popen("../can-utils-2023.03/candump vcan0", "r");

    printf("INVIO CHIAVE\n");
    // Invio la mia chiave pubblica ad ogni avvio
    sendkey(pk, fp);
    
    char buffer[50];
    char msgCode[5];

    char tempID[DATA_LENGTH + 1];

    for (int i = 0; i < 5; i++) {
        msgCode[i] = '\0';
    }

    printf("AVVIO LOOP\n");
    int j, k;
    int repeat = 1;
    while (repeat) {
        fgets(buffer, 50, fp);
        j = 9;
        k = 0;
        // Ottengo l'ID che definisce la tipologia di messaggio
        while (!isspace(buffer[j])) {
            msgCode[k] = buffer[j];
            k++;
            j++;
            
        }
        j = 0;
        // Estraggo l'ID del sender
        for(int i = 0; i < DATA_LENGTH; i+=2) {
            tempID[i] = buffer[20 + j];
            tempID[i+1] = buffer[20 + j +1];
            j+=3;
        }
        tempID[DATA_LENGTH] = '\0';

        printf("TEMP ID = %s\n", tempID);
        int id = hexToInt(tempID);

        int code = hexToInt(msgCode);

        switch(code) {
            //ID = 111
            case 273:
                printf("KEY\n");
                if (id < N_ECU && id >= 0 && id != hexToInt(ID_ECU)) {
                    receiveKey(fp, id);
                } else {
                    printf("ID NOT VALID: %d\n", id);
                }
                break;
            //ID = 112
            case 274:
                printf("REQUEST KEY\n");
                sendkey(pk, fp);
                break;
            //ID = 122
            case 290:
                printf("CIPHER\n");
                if (id < N_ECU && id >= 0 && id != hexToInt(ID_ECU)) {
                    receiveCipherTextAndSharedSecret(fp, id);
                } else {
                    printf("ID NOT VALID: %d\n", id);
                }
                break;
            //ID = 123
            case 291:
                printf("REQUEST CIPHER\n");
                pqcrystals_kyber512_ref_enc(ct, ss, publicKeys[id]);
                for (int i = 0; i < pqcrystals_kyber512_BYTES; i++) {
                    sharedKeys[id][i] = ss[i];
                }
                sendCipherText(ct, fp);
                break;
            //ID = A
            case 10:
                printf("CANGEN\n");
                if (!cangen(id, fp)) {
                    printf("Chiave non trovata, invio richiesta\n");
                    char cmd[50];
                    strcpy(cmd, "../can-utils-2023.03/cansend vcan0 123#");
                    strcat(cmd, ID_ECU);
                    printf("TEST: %s\n", cmd);
                    system(cmd);
                    // Pulisco la pipe dal messaggio inviato
                    fgets(buffer, 50, fp);
                }
                break;
            //ID = B
            case 11:
                printf("RECEIVE CANGEN\n");

                if (!isSharedKeyEmpty(id)) {
                    receiveCangen(fp, id);
                } else {
                    printf("Cannot decrypt, no key found");
                }
                break;
            //ID = 0
            case 0:
                printf("STOP\n");
                if (!strcmp(tempID, "FFFFFFFFFFFFFFFF")) {
                    repeat = 0;
                }
                break;
            default:
                printf("OTHER: %s\nINT: %d\n", msgCode, code);
                break;
        }
        printf("TERMINATO WHILE\n");

    }

    printf("FINE\n");

    // Termino il processo associato alla pipe
    pid_t pid = getpid();
    char num[8];
    sprintf(num, "%d", pid);

    char* cmd = "ps -eaf | grep \"../can-utils-2023.03/candump vcan0\" | grep ";
    int tempLen = strlen(cmd) + 8;
    char* temp = malloc(tempLen * sizeof(char));
    strcpy(temp, cmd);
    strcat(temp, num);

    // printf("TEMP: %s-\n", temp);
    
    FILE* targetProcess = popen(temp, "r");

    fgets(buffer, 50 ,targetProcess);

    // printf("RESULT: %s\n", buffer);

    int i = 0;
    while(!isspace(buffer[11 + i])) {
        num[i] = buffer[11 + i];
        i++;
    }

    int targetPid;
    sscanf(num, "%d", &targetPid);

    //printf("NUM: %d\n", targetPid);

    kill(targetPid, SIGKILL);

    free(temp);

    pclose(targetProcess);
    pclose(fp);
    printf("CHIUSA LA PIPE\n");
   
    // printf("Cifratura\n\n");
    // int len = encrypt(plainText, PLAIN_LENGTH, ss, nonce, cipherText);

    // printf("Lunghezza restituita: %d\n", len);

    // printf("Ciphertext:");
    // for (int i = 0; i < CIPHER_LENGTH; i++) {
    //     printf(" %u", cipherText[i]);
    // }
    // printf("\n");

    // for (int i = 0; i < PLAIN_LENGTH; i++) {
    //     plainText[i] = 0;
    // }
    // printf("Decifratura\n\n");
    // len = decrypt(cipherText, CIPHER_LENGTH, ss, nonce, plainText);

    // printf("Plaintext:");
    // for (int i = 0; i < PLAIN_LENGTH; i++) {
    //     printf(" %u", plainText[i]);
    // }
    // printf("\n");


    return test;
}

// #include <openssl/conf.h>
// #include <openssl/evp.h>
// #include <openssl/err.h>
// #include <string.h>

// int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
//             unsigned char *iv, unsigned char *ciphertext);
// int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
//             unsigned char *iv, unsigned char *plaintext);

// int main (void)
// {
//     /*
//      * Set up the key and iv. Do I need to say to not hard code these in a
//      * real application? :-)
//      */

//     /* A 256 bit key */
//     unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

//     /* A 128 bit IV */
//     unsigned char *iv = (unsigned char *)"0123456789012345";

//     /* Message to be encrypted */
//     unsigned char *plaintext =
//         (unsigned char *)"The quick brown fox jumps over the lazy dog";

//     /*
//      * Buffer for ciphertext. Ensure the buffer is long enough for the
//      * ciphertext which may be longer than the plaintext, depending on the
//      * algorithm and mode.
//      */
//     unsigned char ciphertext[128];

//     /* Buffer for the decrypted text */
//     unsigned char decryptedtext[128];

//     int decryptedtext_len, ciphertext_len;

//     /* Encrypt the plaintext */
//     ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
//                               ciphertext);

//     /* Do something useful with the ciphertext here */
//     printf("Ciphertext is:\n");
//     BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

//     /* Decrypt the ciphertext */
//     decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
//                                 decryptedtext);

//     /* Add a NULL terminator. We are expecting printable text */
//     decryptedtext[decryptedtext_len] = '\0';

//     /* Show the decrypted text */
//     printf("Decrypted text is:\n");
//     printf("%s\n", decryptedtext);


//     return 0;
// }


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
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