
#include "HalfCipher.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    void HalfCipher::reserve(std::shared_ptr<const SEALContext::ContextData> context_data_ptr)
    {
        auto &parms = context_data_ptr->parms();

        size_t new_data_capacity = mul_safe(parms.poly_modulus_degree(), parms.coeff_modulus().size());
        size_t new_data_size = min<size_t>(new_data_capacity, data_.size());

        data_.reserve(new_data_capacity);
        data_.resize(new_data_size);
    }

    void multiply_plain_normal_inplace(std::shared_ptr<const SEALContext::ContextData> context_data, HalfCipher &encrypted, 
                                        const Plaintext &plain, MemoryPoolHandle pool)
    {
        auto &parms = context_data->parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        uint64_t plain_upper_half_threshold = context_data->plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data->plain_upper_half_increment();
        auto ntt_tables = iter(context_data->small_ntt_tables());

        size_t encrypted_size = 1;
        size_t plain_coeff_count = plain.coeff_count();
        //size_t plain_nonzero_coeff_count = plain.nonzero_coeff_count();

        auto temp(allocate_zero_poly(coeff_count, coeff_modulus_size, pool));

        if (!context_data->qualifiers().using_fast_plain_lift)
        {
            StrideIter<uint64_t *> temp_iter(temp.get(), coeff_modulus_size);

            SEAL_ITERATE(iter(plain.data(), temp_iter), plain_coeff_count, [&](auto I) {
                auto plain_value = get<0>(I);
                if (plain_value >= plain_upper_half_threshold)
                {
                    add_uint(plain_upper_half_increment, coeff_modulus_size, plain_value, get<1>(I));
                }
                else
                {
                    *get<1>(I) = plain_value;
                }
            });

            context_data->rns_tool()->base_q()->decompose_array(temp_iter, coeff_count, pool);
        }
        else
        {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the coeff_modulus
            // primes.
            RNSIter temp_iter(temp.get(), coeff_count);
            SEAL_ITERATE(iter(temp_iter, plain_upper_half_increment), coeff_modulus_size, [&](auto I) {
                SEAL_ITERATE(iter(get<0>(I), plain.data()), plain_coeff_count, [&](auto J) {
                    get<0>(J) =
                        SEAL_COND_SELECT(get<1>(J) >= plain_upper_half_threshold, get<1>(J) + get<1>(I), get<1>(J));
                });
            });
        }

        RNSIter temp_iter(temp.get(), coeff_count);
        ntt_negacyclic_harvey(temp_iter, coeff_modulus_size, ntt_tables);

        HalfCipher::ct_coeff_type* enc_pt = encrypted.data();
        PolyIter Iter_enc(enc_pt, coeff_count, coeff_modulus_size);

        SEAL_ITERATE(iter(Iter_enc), encrypted_size, [&](auto I) {
            SEAL_ITERATE(iter(I, temp_iter, coeff_modulus, ntt_tables), coeff_modulus_size, [&](auto J) {
                // Lazy reduction
                ntt_negacyclic_harvey_lazy(get<0>(J), get<3>(J));
                dyadic_product_coeffmod(get<0>(J), get<1>(J), coeff_count, get<2>(J), get<0>(J));
                inverse_ntt_negacyclic_harvey(get<0>(J), get<3>(J));
            });
        });

    }
}