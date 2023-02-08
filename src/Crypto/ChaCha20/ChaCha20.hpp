#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <array>

const std::vector<unsigned char> chacha20_enc(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, const std::array<unsigned char,12>& IV){
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx,EVP_chacha20(),key.data(),IV.data());
    std::vector<unsigned char> outData(data.size());
    auto l1=0,l2=0;
    EVP_EncryptUpdate(ctx,outData.data(),&l1,data.data(),data.size());
    EVP_EncryptFinal(ctx,outData.data()+l1,&l2);
    outData.resize(l1+l2);
    EVP_CIPHER_CTX_free(ctx);
    return outData;
}

template<size_t size>
const std::array<unsigned char, size> GenerateIV(){
    std::array<unsigned char, size> iv;
    RAND_bytes(iv.data(),iv.size());
    return iv;
}

const std::vector<unsigned char> chacha20_dec(const std::vector<unsigned char>& encData,const std::vector<unsigned char>& key, const std::array<unsigned char,12>& IV){
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx,EVP_chacha20(),key.data(),IV.data());
    auto l1=0,l2=0;
    std::vector<unsigned char> outData(encData.size());
    EVP_DecryptUpdate(ctx,outData.data(),&l1,encData.data(),encData.size());
    EVP_DecryptFinal(ctx,outData.data()+l1,&l2);
    outData.resize(l1+l2);
    EVP_CIPHER_CTX_free(ctx);
    return outData;
}