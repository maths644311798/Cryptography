#pragma once
#include "lweSecretKey.hpp"
#include "lweCipherText.h"


class lweDecryptor {
private:
	lweSecretKey sk_;
	seal::SEALContext context_;
    
public:
	lweDecryptor(const seal::SEALContext& context, const lweSecretKey& sk)
		: sk_(sk), context_(context){
            // Seal's copy constructor is enough
        };


std::vector<uint64_t> DoDecrypt(const LWECT& ct) 
{
	std::size_t num_coeff = ct.poly_modulus_degree();

	std::shared_ptr<const seal::SEALContext::ContextData> context_data = context_.get_context_data(ct.parms_id());
	std::vector<uint64_t> return_result(context_data->parms().coeff_modulus().size());

	for(unsigned j=0; j<context_data->parms().coeff_modulus().size(); ++j)
	{
	const seal::Modulus& modulus = context_data->parms().coeff_modulus()[j];
		
	// Calculate c0 + c1 * s
    // If modulus switch is applied, only one modulu is left
    uint64_t result{0};
	uint64_t modTemp{0};
	const uint64_t* op0 = sk_.get_sk().data().data();
	const uint64_t* op1 = ct.get_ct1().data() + j * num_coeff;

	seal::Modulus plain_modulus = context_data->parms().plain_modulus(); // t

	for (std::size_t i = 0; i < num_coeff; i++) {
		modTemp = seal::util::multiply_uint_mod(*(op0 + i), *(op1 + i), modulus);
		result = seal::util::add_uint_mod(result, modTemp, modulus);
	}

	// If fastPIR parameters is used, don't use this line, although it's faster
	// than above loop
    // result = seal::util::dot_product_mod(op0, op1, num_coeff, modulus);

	result = seal::util::add_uint_mod(result, ct.get_ct0()[j], modulus);

    // Times t/Q
	uint64_t resultTmp[2]{0, 0};
	seal::util::multiply_uint64(result, plain_modulus.value(), reinterpret_cast<unsigned long long*>(resultTmp)); // Times t
	uint64_t decrypt_result[2]{0, 0};
	uint64_t half_modulus = modulus.value() >> 1; // Round
	seal::util::add_uint(resultTmp, 2, half_modulus, resultTmp);
	seal::util::divide_uint128_inplace(resultTmp, modulus.value(), decrypt_result); // Divide Q, floor function

	return_result[j] = decrypt_result[0];

	// If modulus switch is applied before tranformation from RLWE ciphertext to LWE ciphertext, 
	// CRT is no longer needed, for usage, see https://github.com/microsoft/SEAL/blob/main/native/src/seal/util/rns.cpp
	}
	return return_result;
}
};
