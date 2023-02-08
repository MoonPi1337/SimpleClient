#include "Crypto/EC/EC.hpp"
#include "Crypto/HASH/SHA256.hpp"
#include "Crypto/AES/AES.hpp"

#include <chrono>

struct Message final{
    pEC sender;
    pEC receiver;

    std::vector<unsigned char> data;

    std::array<unsigned char, 16> iv; //For Aes
    
    time_t timestamp;

    std::array<std::string,2> signature; // 0 - R, 1 - S numbers in ECDSA

    const std::string GetHash(){
        std::vector<unsigned char> _data = data;
        _data.insert(_data.end(),iv.begin(),iv.end());
        auto key = receiver.GetPkey();
        _data.insert(_data.end(),key.begin(),key.end());
        auto _timestamp = std::to_string(timestamp);
        _data.insert(_data.end(),_timestamp.begin(),_timestamp.end());
        return sha256(_data);
    }

    const bool Verify(const bool& checkTime = true){ //digital signature will be incorrect if we change pEC sender
        auto res = sender.Verify(GetHash(),signature);
        if(checkTime){
            const auto current = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            return res && (std::abs(current - timestamp) <= 15);
        }
        return res;
    }
    
    const std::vector<unsigned char> DecryptViaSender(sEC _sender){
        auto key = _sender.Exchange(receiver);
        return aes256_cbc_dec(data,key,iv);
    }
    const std::vector<unsigned char> DecryptViaReceiver(sEC _receiver){
        auto key = _receiver.Exchange(sender);
        return aes256_cbc_dec(data,key,iv);
    }
};
