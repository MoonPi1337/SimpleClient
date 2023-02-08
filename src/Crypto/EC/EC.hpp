#pragma once
#include <iostream>
#include <vector>
#include <array>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ecdsa.h>


class pEC final{
private:
    EC_POINT* point = nullptr;
    EC_GROUP* gp = nullptr;
    const int group;
public:
    pEC(const int& group = NID_secp256k1):group(group){}

    pEC(const std::string& pKey, const int& group = NID_secp256k1):group(group){
        gp = EC_GROUP_new_by_curve_name(group);
        if(!gp){
            throw std::runtime_error("EC_GROUP_new_by_curve_name");
        }
        point = EC_POINT_hex2point(gp,pKey.c_str(),nullptr,nullptr);
        if(!point){
            EC_GROUP_free(gp);
            throw std::runtime_error("EC_POINT_hex2point");
        }
    }
    pEC(const pEC& other):group(group){
        gp = EC_GROUP_new_by_curve_name(other.group);
        EC_GROUP_copy(gp,other.gp);
        point = EC_POINT_new(gp);
        EC_POINT_copy(point,other.point);
    }
    pEC& operator=(const pEC& other){
        if(gp){
            EC_GROUP_free(gp);
        }
        if(point){
            EC_POINT_free(point);
        }
        gp = EC_GROUP_new_by_curve_name(other.group);
        EC_GROUP_copy(gp,other.gp);
        point = EC_POINT_new(gp);
        EC_POINT_copy(point,other.point);
        return *this;
    }
    ~pEC(){
        if(gp){
            EC_GROUP_free(gp);
        }
        if(point){
            EC_POINT_free(point);
        }
    }

    const std::string GetPkey(){
        return std::string(EC_POINT_point2hex(gp,point,POINT_CONVERSION_UNCOMPRESSED,nullptr));
    }

    const bool Verify(const std::string& hash, const std::array<std::string,2>& signature){
        auto R = BN_new();
        if(!R){
            return false;
        }
        auto S = BN_new();
        if(!S){
            BN_free(R);
            return false;
        }

        if(!BN_hex2bn(&R,signature.front().c_str())){
            BN_free(S);
            BN_free(R);
            return false;
        }

        if(!BN_hex2bn(&S,signature.back().c_str())){
            BN_free(S);
            BN_free(R);
            return false;
        }

        auto sig = ECDSA_SIG_new();
        if(!sig){
            BN_free(S);
            BN_free(R);
            return false;
        }
        if(!ECDSA_SIG_set0(sig,R,S)){
            ECDSA_SIG_free(sig);
            if(S){
                BN_free(S);
            }
            if(R){
                BN_free(R);
            }
            return false;
        }
        auto key = EC_KEY_new();
        if(!key){
            ECDSA_SIG_free(sig);
            return false;
        }
        if(!EC_KEY_set_group(key,gp)){
            EC_KEY_free(key);
            ECDSA_SIG_free(sig);
            return false;
        }
        if(!EC_KEY_set_public_key(key,point)){
            EC_KEY_free(key);
            ECDSA_SIG_free(sig);
            return false;
        }

        auto res = ECDSA_do_verify(reinterpret_cast<const unsigned char*>(hash.c_str()),hash.size(),sig,key);
        EC_KEY_free(key);
        ECDSA_SIG_free(sig);
        return res==1;
    }

    friend std::ostream& operator<<(std::ostream& os, const pEC& key){
        os << "Public: " << EC_POINT_point2hex(key.gp,key.point,POINT_CONVERSION_UNCOMPRESSED,nullptr);
        return os;
    }
    friend class sEC;
};

class sEC final{
private:
    EC_KEY* key = nullptr;
    const int group;
public:
    sEC(const int& group = NID_secp256k1):group(group){
        key = EC_KEY_new_by_curve_name(group);
        if(!key){
            throw std::runtime_error("EC_KEY_new_by_curve_name");
        }
        if(!EC_KEY_generate_key(key)){
            EC_KEY_free(key);
            throw std::runtime_error("EC_KEY_generate_key");
        }
    }
    sEC(const std::string& skey, const std::string& pkey, const int& group = NID_secp256k1):group(group){
        key = EC_KEY_new_by_curve_name(group);
        if(!key){
            throw std::runtime_error("EC_KEY_new_by_curve_name");
        }
        auto bn = BN_new();
        if(!bn){
            EC_KEY_free(key);
            throw std::runtime_error("BN_new");
        }
        if(!BN_hex2bn(&bn,static_cast<const char*>(skey.c_str()))){
            EC_KEY_free(key);
            BN_free(bn);
            throw std::runtime_error("BN_hex2bn");
        }
        if(EC_KEY_set_private_key(key,bn)==0){
            EC_KEY_free(key);
            BN_free(bn);
            throw std::runtime_error("EC_KEY_set_private_key");
        }

        auto gp = EC_GROUP_new_by_curve_name(group);
        if(!gp){
            EC_KEY_free(key);
            BN_free(bn);
            throw std::runtime_error("EC_GROUP_new_by_curve_name");
        }
        auto point = EC_POINT_hex2point(gp,static_cast<const char*>(pkey.c_str()),nullptr,nullptr);
        if(!point){
            EC_GROUP_free(gp);
            EC_KEY_free(key);
            BN_free(bn);
            throw std::runtime_error("EC_POINT_bn2point");
        }
        BN_free(bn);
        EC_GROUP_free(gp);
        if(EC_KEY_set_public_key(key,point)==0){
            EC_KEY_free(key);
            throw std::runtime_error("EC_KEY_set_public_key");
        }
    }

    const std::string GetPkey(){
        auto pub = EC_KEY_get0_public_key(key);
        auto gp = EC_KEY_get0_group(key);

        if(!pub || !gp){
            throw std::runtime_error("EC_KEY_get0_public_key | EC_KEY_get0_group");
        }

        std::string pkey(EC_POINT_point2hex(gp,pub,POINT_CONVERSION_UNCOMPRESSED,nullptr));
        return pkey;
    };

    const std::string GetSKey(){
        auto prv = EC_KEY_get0_private_key(key);
        if(!prv){
            throw std::runtime_error("EC_KEY_get0_private_key");
        }
        std::string skey(BN_bn2hex(prv));
        return skey;
    }

    const pEC GetKey(){
        return pEC(GetPkey(),group);
    }

    const std::array<std::string,2> Sign(const std::string& hash){
        auto sig = ECDSA_do_sign(reinterpret_cast<const unsigned char*>(hash.c_str()),hash.size(),key);
        std::array<std::string,2> res;
        if(sig){
            auto R = ECDSA_SIG_get0_r(sig);
            auto S = ECDSA_SIG_get0_s(sig);

            res[0] = std::string(BN_bn2hex(R));
            res[1] = std::string(BN_bn2hex(S));
            ECDSA_SIG_free(sig);
        }
        return res;
    }

    const bool Verify(const std::string& hash, const std::array<std::string,2>& signature){
        auto R = BN_new();
        if(!R){
            return false;
        }
        auto S = BN_new();
        if(!S){
            BN_free(R);
            return false;
        }

        if(!BN_hex2bn(&R,signature.front().c_str())){
            BN_free(S);
            BN_free(R);
            return false;
        }

        if(!BN_hex2bn(&S,signature.back().c_str())){
            BN_free(S);
            BN_free(R);
            return false;
        }

        auto sig = ECDSA_SIG_new();
        if(!sig){
            BN_free(S);
            BN_free(R);
            return false;
        }
        if(!ECDSA_SIG_set0(sig,R,S)){
            ECDSA_SIG_free(sig);
            if(S){
                BN_free(S);
            }
            if(R){
                BN_free(R);
            }
            return false;
        }
        auto res = ECDSA_do_verify(reinterpret_cast<const unsigned char*>(hash.c_str()),hash.size(),sig,key);
        ECDSA_SIG_free(sig);
        return res==1;
    }

    sEC(const sEC& other):group(other.group){
        key = EC_KEY_new();
        EC_KEY_copy(key,other.key);
    }
    sEC& operator=(const sEC& other){
        if(key){
            EC_KEY_free(key);
        }
        key = EC_KEY_new();
        EC_KEY_copy(key,other.key);
        return *this;
    }

    friend std::ostream& operator<<(std::ostream& os, const sEC& mKey){
        auto prv = EC_KEY_get0_private_key(mKey.key);
        auto pub = EC_KEY_get0_public_key(mKey.key);
        auto gp = EC_KEY_get0_group(mKey.key);
        if(prv){
            auto hex = BN_bn2hex(prv);
            if(hex){
                os << "Private: " << hex;
                OPENSSL_free(hex);
            }
        }
        if(pub && gp){
            if(prv){
                os << "\n";
            }
            auto hex = EC_POINT_point2hex(gp,pub,POINT_CONVERSION_UNCOMPRESSED,nullptr);
            if(hex){
                os << "Public: " << hex;
                OPENSSL_free(hex);
            }
        }
        return os;
    }
    const std::vector<unsigned char> Exchange(const pEC& _key){
        std::vector<unsigned char> res;
        auto field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
        auto len = (field_size+7)/8; //convert len to bytes
        res.resize(len);
        len = ECDH_compute_key(res.data(),len,_key.point,key,nullptr);
        res.resize(len);
        return res;
    }
    ~sEC(){
        if(key){
            EC_KEY_free(key);
        }
    }
};
