#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <array>

const std::vector<unsigned char> aes256_cbc_enc(const std::vector<unsigned char>& plain, const std::vector<unsigned char>& key, const std::array<unsigned char,16>& iv){
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx,EVP_aes_256_cbc(),key.data(),iv.data());
    std::vector<unsigned char> outData(plain.size()*2);
    auto l1 = 0;
    EVP_EncryptUpdate(ctx,outData.data(),&l1,plain.data(),plain.size());
    auto l2 = 0;
    EVP_EncryptFinal(ctx,outData.data()+l1,&l2);
    outData.resize(l1+l2);
    EVP_CIPHER_CTX_free(ctx);
    return outData;
}

const std::array<unsigned char, 16> GenerateIV(){
    std::array<unsigned char, 16> iv;
    RAND_bytes(iv.data(),iv.size());
    return iv;
}

const std::vector<unsigned char> aes256_cbc_dec(const std::vector<unsigned char>& encData, const std::vector<unsigned char>& key, const std::array<unsigned char,16>& iv){
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx,EVP_aes_256_cbc(),key.data(),iv.data());
    auto l1 = 0, l2 = 0;
    std::vector<unsigned char> outData(encData.size());
    EVP_DecryptUpdate(ctx,outData.data(),&l1,encData.data(),encData.size());
    EVP_DecryptFinal(ctx,outData.data()+l1,&l2);
    outData.resize(l1+l2);
    EVP_CIPHER_CTX_free(ctx);
    return outData;
}