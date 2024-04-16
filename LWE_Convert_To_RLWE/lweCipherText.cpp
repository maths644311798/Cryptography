#include "lweCipherText.h"


LWECT::LWECT(const seal::Ciphertext& RLWECT, const std::size_t coeff_index,
	const seal::SEALContext& context) {
	// Read parameters
	std::size_t num_coeff = RLWECT.poly_modulus_degree(); 
	poly_modulus_degree_ = num_coeff;
	std::shared_ptr<const seal::SEALContext::ContextData> context_data =
	    context.first_context_data();
	const seal::EncryptionParameters& parms = context_data->parms(); 
	ct0.resize(parms.coeff_modulus().size());
	ct1.parms_id() = seal::parms_id_zero; 
	ct1.resize(num_coeff * (parms.coeff_modulus().size()));
	ct1.parms_id() = RLWECT.parms_id();

	for(unsigned int j=0; j < parms.coeff_modulus().size(); ++j)
	{
		const seal::Modulus& modulus = parms.coeff_modulus()[j]; 

		// Read data from RLWE ciphertext, write to LWE ciphertext after transformation
		// The resize function will check whether ciphertext is ntt form firstly, which
		// checks if parms_id is parms_id_zero, so following operations is needed
		uint64_t* destination_ptr = ct1.data() + j*num_coeff;
		const seal::Ciphertext::ct_coeff_type* source_ptr = RLWECT.data(1) + j*num_coeff; // Iterator points to head of c1

		// Extraction, see https://www.wolai.com/pxxu1LrqTjXTVbcN98aH6U for details
		auto reverse_ptr = std::reverse_iterator<uint64_t*>(destination_ptr + coeff_index + 1);
		std::copy_n(source_ptr, coeff_index + 1, reverse_ptr);
		// Reverse and negate coefficients in index [coeff_index + 1, num_coeff]
		reverse_ptr = std::reverse_iterator<uint64_t*>(destination_ptr + num_coeff);
		std::transform(
			source_ptr + coeff_index + 1, source_ptr + num_coeff, reverse_ptr,
			[&](uint64_t u) {
				return seal::util::negate_uint_mod(u, modulus);
			}
		);
		ct0[j] = RLWECT.data(0)[j*num_coeff + coeff_index];
	}

	ct1.parms_id() = RLWECT.parms_id();	
}

void Compute_N_inverse(const seal::SEALContext &context, std::vector<seal::Plaintext::pt_coeff_type> &N_inverse)
{
	auto parms = context.first_context_data()->parms();
	std::size_t num_coeff = parms.poly_modulus_degree();

	std::vector<seal::Plaintext::pt_coeff_type> vector_num_coeff(parms.coeff_modulus().size(), num_coeff);

	for(unsigned int i = 0; i < parms.coeff_modulus().size(); ++i)
	{
		seal::util::try_invert_uint_mod(vector_num_coeff[i], parms.coeff_modulus()[i], N_inverse[i]);
	}
	return;
}

void Prepare_Galois(const seal::SEALContext &context, seal::KeyGenerator &keygen, seal::GaloisKeys &galois_keys)
{
	std::size_t num_coeff = context.first_context_data()->parms().poly_modulus_degree();
	int log2_num_coeff = std::log2(num_coeff);

	std::vector<std::uint32_t> galois_elements(log2_num_coeff);
	int pow_of_two = num_coeff;
	for(unsigned int k = log2_num_coeff; k >= 1; --k)
	{
		galois_elements[k-1] = pow_of_two + 1;
		pow_of_two >>= 1;
	}
	keygen.create_galois_keys(galois_elements, galois_keys);
	return;
}

void EvalTr(const seal::SEALContext &context, const seal::Ciphertext &src,
			seal::Ciphertext &des, seal::GaloisKeys &galois_keys,
			const unsigned int n)
{
	auto parms = context.first_context_data()->parms();
	std::size_t num_coeff = parms.poly_modulus_degree();
	unsigned int pow_of_two = num_coeff;

	des = src;
	seal::Ciphertext temp(des);
	seal::Evaluator evaluator(context);
	while(pow_of_two > n)
	{
		evaluator.apply_galois(des, pow_of_two + 1, galois_keys, temp);
		evaluator.add_inplace(des, temp);
		pow_of_two >>= 1;
	}
}

void LWE_ConvertTo_RLWE(const seal::SEALContext &context, const LWECT &src,
						seal::Ciphertext &des, seal::GaloisKeys &galois_keys,
						const std::vector<seal::Plaintext::pt_coeff_type> &N_inverse)
{
	//des should be initialized like seal::Ciphertext des(context);
	auto parms = context.first_context_data()->parms();
	std::size_t num_coeff = parms.poly_modulus_degree();
	unsigned int log2_num_coeff = std::log2(num_coeff);
	seal::Evaluator evaluator(context);

	seal::Plaintext src_ct1(src.get_ct1());
	std::vector<uint64_t> src_ct0(src.get_ct0());

	for(unsigned int i = 0; i < parms.coeff_modulus().size(); ++i)
	{
		seal::util::multiply_poly_scalar_coeffmod(src.get_ct1().data() + i * num_coeff, 
			num_coeff, N_inverse[i], parms.coeff_modulus()[i], src_ct1.data() + i * num_coeff);
		unsigned long long tmp[2];
		seal::util::multiply_uint64(src_ct0[i], N_inverse[i], tmp);
		src_ct0[i] = ((__uint128_t(tmp[1]) << 64) + tmp[0]) % parms.coeff_modulus()[i].value();
	}

	des.resize(2);
	des.is_ntt_form() = false;
	des.parms_id() = context.first_parms_id();
	//memset(des.data(0),0, parms.coeff_modulus().size() * sizeof(seal::Ciphertext::ct_coeff_type) * num_coeff);
	for(unsigned int j=0; j<parms.coeff_modulus().size(); ++j)
	{
		des.data(0)[j*num_coeff] = src_ct0[j];
	}
	
	std::copy_n(src_ct1.data(), num_coeff * parms.coeff_modulus().size(), des.data(1));

	int pow_of_two = num_coeff;
	seal::Ciphertext temp(des);
	for(unsigned int k = 1; k <= log2_num_coeff; ++k)
	{
		evaluator.apply_galois(des, pow_of_two + 1, galois_keys, temp);
		evaluator.add_inplace(des, temp);
		pow_of_two >>= 1;
	}
	return;
}

seal::Ciphertext PackLWEs(const seal::SEALContext &context, std::vector<unsigned long> index_set,
		std::vector<seal::Ciphertext> const &ct, seal::GaloisKeys &galois_keys)
{
	if (index_set.size() == 1) return ct[index_set[0]];
	auto parms = context.first_context_data()->parms();
	std::size_t num_coeff = parms.poly_modulus_degree();
	seal::Ciphertext result(context), ct_even(context), ct_odd(context);
	std::vector<unsigned long> even_index(index_set.size() >> 1), odd_index(index_set.size() >> 1);

	for(unsigned int i = 0; i < even_index.size(); ++i)
	{
		even_index[i] = index_set[i << 1];
		odd_index[i] = index_set[(i << 1) + 1];
	}
	ct_even = PackLWEs(context, even_index, ct, galois_keys);
	ct_odd = PackLWEs(context, odd_index, ct, galois_keys);
	seal::Plaintext XN2l(num_coeff, num_coeff);
	*(XN2l.data() + num_coeff / index_set.size()) = 1;


	seal::Evaluator evaluator(context);
	seal::Ciphertext tmp(context), tmp2(context);
	evaluator.multiply_plain(ct_odd, XN2l, tmp);
	evaluator.add(ct_even, tmp, result);
	evaluator.sub(ct_even, tmp, tmp2);
	evaluator.apply_galois_inplace(tmp2, index_set.size() + 1, galois_keys);
	evaluator.add_inplace(result, tmp2);
	return result;
}

void LWEs_ConvertTo_RLWE(const seal::SEALContext &context, const std::vector<LWECT> &src,
						seal::Ciphertext &des, seal::GaloisKeys &galois_keys,
						const std::vector<seal::Plaintext::pt_coeff_type> &N_inverse)
{
	auto parms = context.first_context_data()->parms();
	std::size_t num_coeff = parms.poly_modulus_degree();
	unsigned int log2_num_coeff = std::log2(num_coeff);

	des.resize(2);
	des.is_ntt_form() = false;
	des.parms_id() = context.first_parms_id();

	std::vector<seal::Ciphertext> src_ct(src.size(), des);
	std::vector<unsigned long> index_set(src.size());
	
	for(unsigned int j = 0; j < src.size(); ++j)
	{
		index_set[j] = j;
	for(unsigned int i = 0; i < parms.coeff_modulus().size(); ++i)
	{
		seal::util::multiply_poly_scalar_coeffmod(src[j].get_ct1().data() + i * num_coeff, 
			num_coeff, N_inverse[i], parms.coeff_modulus()[i], src_ct[j].data(1) + i * num_coeff);
		unsigned long long tmp[2];
		seal::util::multiply_uint64(src[j].get_ct0()[i], N_inverse[i], tmp);
		src_ct[j].data(0)[i*num_coeff] = ((__uint128_t(tmp[1]) << 64) + tmp[0]) % parms.coeff_modulus()[i].value();
	}
	}

	seal::Ciphertext ct = PackLWEs(context, index_set, src_ct, galois_keys);
	EvalTr(context, ct, des, galois_keys, src.size());
	return;
}
