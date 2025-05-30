
#pragma once
#include <set>
#include <sstream>
#include <vector>
#include <chrono>

#include "seal/util/defines.h"
#include "seal/context.h"
#include "seal/util/rlwe.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/encryptionparams.h"
#include "seal/plaintext.h"
#include "include.h"
#include "lweSecretKey.hpp"

using namespace std;

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
                ct_size * poly_modulus_degree * coeff_modulus_size);
}

class Timer
{
public:
    decltype(std::chrono::system_clock::now()) t_;

    Timer();

    void StopWatch();
};

/*
Assume the base z is smaller than any modulus qi
*/
class BaseDecompose
{
public:
    BaseDecompose(const seal::SEALContext &context, const std::uint64_t oz = 2048);

/* 
x is in binary form. The result is assumed to be in (-z/2, z/2].
Turning to the RNS, the result vector has size t * coeff_modulus_size.
*/
    std::vector<std::uint64_t> Decompose(const std::uint64_t *x, std::uint64_t uint64_count) const;

//z is the base. t = floor(log_z(q)) + 1 <= 56.
//Require 2q < z^t
    std::uint64_t z{2048}, t{0};
//We only consider first_context_data now.
    std::shared_ptr<const seal::SEALContext::ContextData> context_data;
};