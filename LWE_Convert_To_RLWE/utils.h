
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
                ct_size * poly_modulus_degree * coeff_modulus_size);
}

class Timer
{
public:
    decltype(std::chrono::system_clock::now()) t_;

    Timer();

    void StopWatch();
};

void switch_key_inplace_ntt(const seal::SEALContext &context, seal::Ciphertext &encrypted, 
                        seal::util::ConstRNSIter target_iter, const KSwitchKeys &kswitch_keys, 
                        size_t kswitch_keys_index,
                        seal::MemoryPoolHandle pool =  seal::MemoryManager::GetPool());

inline void BFV_galois_inplace_ntt(const seal::SEALContext &context, seal::Ciphertext &c, uint32_t galois_elt,
                            const GaloisKeys &galois_keys, 
                            seal::MemoryPoolHandle pool =  seal::MemoryManager::GetPool())
{
    auto galois_tool = context.key_context_data()->galois_tool();

    auto context_data = context.get_context_data(c.parms_id());
    auto &parms = context_data->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    seal::Evaluator evaluator(context);
    auto &key_vector = galois_keys.data()[GaloisKeys::get_index(galois_elt)];

    size_t encrypted_size = c.size();
    auto encrypted_iter = seal::util::iter(c);

    SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count, coeff_modulus_size, pool);

    galois_tool->apply_galois_ntt(encrypted_iter[0], coeff_modulus_size, galois_elt, temp);
    seal::util::set_poly(temp, coeff_count, coeff_modulus_size, c.data(0));

    galois_tool->apply_galois_ntt(encrypted_iter[1], coeff_modulus_size, galois_elt, temp);

    seal::util::set_zero_poly(coeff_count, coeff_modulus_size, c.data(1));


    switch_key_inplace_ntt(context, c, temp, static_cast<const KSwitchKeys &>(galois_keys), 
                        GaloisKeys::get_index(galois_elt), pool);

}

class BaseDecompose
{
public:
    BaseDecompose(const std::uint64_t &oz, const seal::Modulus &oq);

//the result is assumed to be in (-z/2, z/2]
    std::vector<std::uint64_t> Decompose(std::uint64_t x);

//z is the base. t = floor(log_z(q)) + 1 <= 56.
    std::uint64_t z;
    seal::Modulus q;
    std::vector<std::uint64_t> gz;
};