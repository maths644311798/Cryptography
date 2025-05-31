
#pragma once
#include <set>
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>

#include "seal/util/defines.h"
#include "seal/context.h"
#include "seal/util/rlwe.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/encryptionparams.h"
#include "seal/dynarray.h"
#include "seal/util/iterator.h"

namespace seal
{
    class HalfCipher
    {
        public:
        using ct_coeff_type = std::uint64_t;

        HalfCipher(MemoryPoolHandle pool = MemoryManager::GetPool()) : data_(std::move(pool))
        {}

        HalfCipher(const SEALContext &context, MemoryPoolHandle pool = MemoryManager::GetPool())
            : data_(std::move(pool))
        {
            auto parms_id = context.first_parms_id();
            auto context_data_ptr = context.get_context_data(parms_id);
            reserve(context_data_ptr);
        }

        HalfCipher(std::shared_ptr<const SEALContext::ContextData> context_data_ptr, 
                    MemoryPoolHandle pool = MemoryManager::GetPool())
            : data_(std::move(pool))
        {
            reserve(context_data_ptr);
        }

        HalfCipher(const Ciphertext &c, size_t poly_index = 0, MemoryPoolHandle pool = MemoryManager::GetPool())
            : data_(std::move(pool))
        {
            size_t new_data_capacity = util::mul_safe(c.poly_modulus_degree(), c.coeff_modulus_size());
            data_.reserve(new_data_capacity);
            data_.resize(new_data_capacity);
            std::copy_n(c.data(poly_index), new_data_capacity, data_.begin());
        }

        HalfCipher(HalfCipher &other)
            :data_(other.data_)
        {

        }        

        ~HalfCipher()
        {
            //implicit data_.~DynArray<ct_coeff_type>();
        }

        void reserve(std::shared_ptr<const SEALContext::ContextData> context_data_ptr);

        inline ct_coeff_type *data() noexcept
        {
            return data_.begin();
        }

        inline const ct_coeff_type *data() const noexcept
        {
            return data_.cbegin();
        }

        inline HalfCipher &operator=(const HalfCipher &assign)
        {
            if (this == &assign)
            {
                return *this;
            }
            data_ = assign.data_;
            return *this;
        }

        DynArray<ct_coeff_type> data_;
    };


    //des should be initialized like Ciphertext(const SEALContext &context, parms_id_type parms_id...)
    inline void ComposeCipher(const HalfCipher &c0, const HalfCipher &c1, Ciphertext &des)
    {
        des.resize(2);
        size_t half_data_capacity = util::mul_safe(des.poly_modulus_degree(), des.coeff_modulus_size());
        std::copy_n(c0.data(), half_data_capacity, des.data(0));
        std::copy_n(c1.data(), half_data_capacity, des.data(1));
    }

    void multiply_plain_normal_inplace(std::shared_ptr<const SEALContext::ContextData> context_data, HalfCipher &encrypted, 
                                        const Plaintext &plain, MemoryPoolHandle pool = MemoryManager::GetPool());
}