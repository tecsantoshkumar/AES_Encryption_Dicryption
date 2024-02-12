/*******************************************************************************
* Function Name  : AES_ECB_encrypt
* Description    : FUNCTION CALL ENCRYPTS THE PLAIN TEXT WITH KEY USING AES 128
* Input          : S
* Output         : None
* Return         : None
*******************************************************************************/
#define AES_KEYSIZE 16  // You may adjust this based on your AES key size

void addPadding(uint8_t *data, size_t dataSize, size_t blockSize) 
{
    size_t paddingSize = blockSize - (dataSize % blockSize);
    for (size_t i = 0; i < paddingSize; ++i) {
        data[dataSize + i] = (uint8_t)paddingSize;
    }
}


void AES_ECB_encrypt(const uint8_t* RoundKey, uint8_t* buf)
{
  Cipher((state_t*)buf, RoundKey);
}

void AES_128_Encrypt(const uint8_t *plaintext, size_t length, const uint8_t *key) 
{
  char localtestbuff[80] = {0};
  
  strcat(localtestbuff,(char*)plaintext);
  
    AES_init_ctx(RoundKey, key);
    memset(HexToChar_Buffer, 0, sizeof(HexToChar_Buffer));
    memset(encryptedData, 0, sizeof(encryptedData));
    
    size_t fullBlocks = length / AES_KEYSIZE;
    size_t remainingBytes = length % AES_KEYSIZE;
    
    // Add PKCS#7 padding
    addPadding((uint8_t *)plaintext, length, AES_KEYSIZE);

    // Process full blocks
    for (size_t i = 0; i < fullBlocks; ++i) {
        AES_ECB_encrypt(RoundKey, (uint8_t *)plaintext + (i * AES_KEYSIZE));
        memcpy(HexToChar_Buffer + (i * AES_KEYSIZE), plaintext + (i * AES_KEYSIZE), AES_KEYSIZE);
    }

    // Process the last block with PKCS#7 padding
    if (remainingBytes > 0) {
        uint8_t lastBlock[16];
        memset(lastBlock, 0, sizeof(lastBlock));
        memcpy(lastBlock, plaintext + (fullBlocks * AES_KEYSIZE), remainingBytes);
        addPadding(lastBlock, remainingBytes, AES_KEYSIZE);
        AES_ECB_encrypt(RoundKey, lastBlock);
        memcpy(HexToChar_Buffer + (fullBlocks * AES_KEYSIZE), lastBlock, AES_KEYSIZE);

        // Update length to include the padding
        length += AES_KEYSIZE - remainingBytes;
    }
    int encrypt_len = length;
    hexToChar((char *)HexToChar_Buffer, (char*)encryptedData, encrypt_len);
}


void AES_ECB_decrypt(const uint8_t* RoundKey, uint8_t* buf)
{
  InvCipher((state_t*)buf, RoundKey);
}


void AES_128_Decrypt(const uint8_t *ciphertext, size_t length, const uint8_t *key) 
{
  AES_init_ctx(RoundKey,key);

  for (size_t i = 0; i < length; i += 16) {
       AES_ECB_decrypt(RoundKey,((uint8_t*)ciphertext +i));
  }
}

#endif
