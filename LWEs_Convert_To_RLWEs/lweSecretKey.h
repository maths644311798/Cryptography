#pragma once

#include "include.h"

class lweSecretKey {
private:
	seal::SecretKey secret_non_ntt_;

public:
	lweSecretKey(const seal::SecretKey& rlwe_sk, const seal::SEALContext& context)
	:secret_non_ntt_(rlwe_sk)
	{
		const seal::EncryptionParameters& parms = context.key_context_data()->parms();
		const std::vector<seal::Modulus>& modulus = parms.coeff_modulus();
		const std::size_t num_coeff = parms.poly_modulus_degree();
		const std::size_t num_modulus = modulus.size();

		std::copy_n(rlwe_sk.data().data(), num_coeff * num_modulus, secret_non_ntt_.data().data());

		if (rlwe_sk.data().is_ntt_form()) {
			const auto* ntt_tables = context.key_context_data()->small_ntt_tables();
			auto* sk_ptr = secret_non_ntt_.data().data();
			for (size_t l = 0; l < num_modulus; l++, sk_ptr += num_coeff) {
				seal::util::inverse_ntt_negacyclic_harvey(sk_ptr, ntt_tables[l]);
			}
		}
	};

	inline seal::SecretKey& get_sk() { return secret_non_ntt_; };
	inline const seal::SecretKey& const_sk() const { return secret_non_ntt_; };
	inline seal::parms_id_type &parms_id() noexcept
    {
        return secret_non_ntt_.data().parms_id();
    }
	inline seal::parms_id_type const &parms_id() const noexcept
    {
        return secret_non_ntt_.data().parms_id();
    }
};
