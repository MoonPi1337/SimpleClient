#include <openssl/sha.h>
#include <string>
#include <array>
#include <sstream>

const std::string sha256(const std::string& text){
    std::array<unsigned char,SHA256_DIGEST_LENGTH> hash;
    SHA256(reinterpret_cast<const unsigned char*>(text.c_str()),text.size(),hash.data());
    std::stringstream ss;
    for(const auto& i : hash){
        ss << std::hex << int(i);
    }
    return ss.str();
};
const std::string sha256(const std::vector<unsigned char>& data){
    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash;
    SHA256(reinterpret_cast<const unsigned char*>(data.data()),data.size(),hash.data());
    std::stringstream ss;
    for(const auto& i : hash){
        ss << std::hex << int(i);
    }
    return ss.str();
}