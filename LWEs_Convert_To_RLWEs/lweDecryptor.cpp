
#include "lweDecryptor.h"

uint64_t lweDecryptor::Decrypt(const LWECT& ct) 
{
	std::size_t num_coeff = ct.poly_modulus_degree();

	std::shared_ptr<const seal::SEALContext::ContextData> context_data = context_.get_context_data(ct.parms_id());
	auto moduli = context_data->parms().coeff_modulus();
	std::vector<uint64_t> result(moduli.size());
	uint64_t return_result(0);
    seal::Modulus plain_modulus = context_data->parms().plain_modulus();

	for(unsigned j = 0; j < moduli.size(); ++j)
	{
		const seal::Modulus& modulus = moduli[j];
			
		// Calculate c0 + c1 * s
		// If modulus switch is applied, only one modulu is left
		uint64_t modTemp{0};
		const uint64_t* op0 = sk_.get_sk().data().data();
		const uint64_t* op1 = ct.get_ct1().data() + j * num_coeff;

		for (std::size_t i = 0; i < num_coeff; i++) {
			modTemp = seal::util::multiply_uint_mod(*(op0 + i), *(op1 + i), modulus);
			result[j] = seal::util::add_uint_mod(result[j], modTemp, modulus);
		}

		// If fastPIR parameters is used, don't use this line, although it's faster
		// than above loop
		// result = seal::util::dot_product_mod(op0, op1, num_coeff, modulus);

		result[j] = seal::util::add_uint_mod(result[j], ct.get_ct0()[j], modulus);

	}
    /* Times t/Q */
	uint64_t resultTmp[2]{0, 0};
	seal::util::multiply_uint64(result[0], plain_modulus.value(), reinterpret_cast<unsigned long long*>(resultTmp)); // Times t
	uint64_t decrypt_result[2]{0, 0};
	uint64_t half_modulus = moduli[0].value() >> 1; // Round
	seal::util::add_uint(resultTmp, 2, half_modulus, resultTmp);
	seal::util::divide_uint128_inplace(resultTmp, moduli[0].value(), decrypt_result); // Divide Q, floor function
	return_result = decrypt_result[0];

	return return_result;
}