
#pragma once
#include <set>
#include <sstream>
#include <vector>
#include <chrono>

#include "seal/context.h"
#include "seal/util/rlwe.h"
#include "seal/util/polyarithsmallmod.h"
#include "include.h"
#include "lweSecretKey.hpp"

using namespace std;

void SymmetricRLWEEncrypt(const seal::SecretKey &sk,
                          const seal::SEALContext &context,
                          const seal::Plaintext &msg_non_ntt, bool need_ntt,
                          bool need_seed, seal::Ciphertext &out_ct);

void SymmetricRLWEEncrypt(const seal::SecretKey &sk,
                          const seal::SEALContext &context,
                          const std::vector<seal::Plaintext> &msg_non_ntt, bool need_ntt,
                          bool need_seed, std::vector<seal::Ciphertext> &out_ct);

void LWE_Key_ConvertTo_RLWE_Key(const seal::SEALContext& context, const lweSecretKey& LWE_key, seal::SecretKey& RLWE_key);

//assume des holds enough memory, des = source
inline void BFV_assign(seal::Ciphertext& des, const seal::Ciphertext& source)
{
    des.parms_id() = source.parms_id();
    des.is_ntt_form() = source.is_ntt_form();
    des.scale() = source.scale();
    size_t coeff_modulus_size = source.coeff_modulus_size();
    size_t poly_modulus_degree = source.poly_modulus_degree();
    size_t ct_size = source.size();
    //des.resize(ct_size);
    std::memcpy(des.data(), source.data(), sizeof(seal::Ciphertext::ct_coeff_type)*
                ct_size*poly_modulus_degree*coeff_modulus_size);
}

class Timer
{
public:
    decltype(std::chrono::system_clock::now()) t_;

    Timer();

    void StopWatch();
};
