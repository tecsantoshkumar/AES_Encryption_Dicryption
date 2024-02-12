/*
1. Nb: This constant represents the number of columns (32-bit words) in the state array. 
       In AES, the state array is a 4x4 matrix of bytes. 
       Since each column consists of 4 bytes, Nb is set to 4.

2. Nk(keysize): This macro calculates the number of 32-bit words in the key based on the key size provided in bits. 
                In AES, the key size can be 128, 192, or 256 bits. Since each word is 32 bits, 
                dividing the key size by 32 gives the number of words (Nk).

3. Nr(keysize): This macro calculates the total number of rounds in the AES encryption process based on the key size. 
                In AES, the number of rounds varies depending on the key size. For a 128-bit key, there are 10 rounds; 
                for a 192-bit key, there are 12 rounds; and for a 256-bit key, there are 14 rounds. 
                This macro calculates the number of rounds (Nr) based on the key size.
*/

#include <stdio.h>

/* Define constants and sbox */
#define Nb 4
#define Nk(keysize) ((int)(keysize / 32))
#define Nr(keysize) ((int)(Nk(keysize) + 6))

int main() {
    // Example usage of macros
    int keysize = 128; // Key size in bits
    int nk = Nk(keysize); // Number of words in the key
    int nr = Nr(keysize); // Number of rounds

    printf("Key size: %d bits\n", keysize);
    printf("Number of words in the key (Nk): %d\n", nk);
    printf("Number of rounds (Nr): %d\n", nr);

    return 0;
}
