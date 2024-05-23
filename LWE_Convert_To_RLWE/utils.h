
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


void SymmetricRLWEEncrypt(const seal::SecretKey &sk,
                          const seal::SEALContext &context,
                          const seal::Plaintext &msg_non_ntt, bool need_ntt,
                          bool need_seed, seal::Ciphertext &out_ct);

void SymmetricRLWEEncrypt(const seal::SecretKey &sk,
                          const seal::SEALContext &context,
                          const std::vector<seal::Plaintext> &msg_non_ntt, bool need_ntt,
                          bool need_seed, std::vector<seal::Ciphertext> &out_ct);

void LWE_Key_ConvertTo_RLWE_Key(const seal::SEALContext& context, const lweSecretKey& LWE_key, seal::SecretKey& RLWE_key);

class Timer
{
public:
    decltype(std::chrono::system_clock::now()) t_;

    Timer();

    void StopWatch();
};
