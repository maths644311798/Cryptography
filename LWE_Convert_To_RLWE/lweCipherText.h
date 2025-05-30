#ifndef LWECIPHERTEXT_H
#define LWECIPHERTEXT_H


#include <cmath>
#include <memory>
#include "include.h"
#include "seal/util/polyarithsmallmod.h"
#include "utils.h"

class LWECT {
public:
	std::vector<uint64_t> ct0; 
	std::vector<uint64_t> ct1; 
	seal::parms_id_type parms_id_ = seal::parms_id_zero;
	std::size_t poly_modulus_degree_{ 0 };

public:
    // coeff_index represents the index to be extracted
	LWECT() = default;
    LWECT(const seal::SEALContext& context, const seal::Ciphertext& RLWECT, 
	const std::size_t coeff_index = 0);
    // Some useful help functions
	inline const std::size_t poly_modulus_degree() const { return poly_modulus_degree_; }
	inline seal::parms_id_type& parms_id() { return parms_id_; }
	inline const seal::parms_id_type& parms_id() const { return parms_id_; }
	inline std::vector<uint64_t>& get_ct1() { return ct1; }
	inline const std::vector<uint64_t>& get_ct1() const { return ct1; }
	inline const std::vector<uint64_t>& get_ct0() const { return ct0; }
};

void Prepare_Galois(const seal::SEALContext &context, seal::KeyGenerator &keygen, seal::GaloisKeys &galois_keys);

//n should be a power of 2
void EvalTr(const seal::SEALContext &context, const LWECT &src,
				seal::Ciphertext &des, seal::GaloisKeys &galois_keys,
				const unsigned int n);

//not thread-safe
class Packer
{
public:

	std::vector<seal::Plaintext::pt_coeff_type> N_inverse;
	// the inverse of N/n mod q
	std::vector<seal::Plaintext::pt_coeff_type> N_over_n_inverse;
	std::vector<seal::Plaintext::pt_coeff_type> n_inverse;
	size_t n_;

	constexpr static size_t tmp_size = 4;
	//not thread-safe
	mutable seal::Ciphertext allocated_tmp[tmp_size];

	Packer() = default;

	/*
	n should be a power of 2, meaning that we want to reserve the
	iN/n-th coefficients, for 0 <= i < n.
	*/
	Packer(const seal::SEALContext &context, const size_t &n);

	void allocate_memory(const seal::SEALContext &context);

	void Compute_inverses(const seal::SEALContext &context);


	//Store an LWE ciphertext to the degree-0 term
	void LWE_ConvertTo_RLWE(const seal::SEALContext &context, const LWECT& src,
							seal::Ciphertext &des, const seal::GaloisKeys &galois_keys,
							seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool()) const;


	//index_set is used to avoid copying lots of Ciphertexts
	seal::Ciphertext PackLWEs(const seal::SEALContext &context, std::vector<unsigned long> index_set,
			std::vector<seal::Ciphertext> const &ct, const seal::GaloisKeys &galois_keys) const;
	//src.size should be a power of 2 and <= poly_degree
	void LWEs_ConvertTo_RLWE(const seal::SEALContext &context, const std::vector<LWECT> &src,
							seal::Ciphertext &des, const seal::GaloisKeys &galois_keys) const;


	/*
	This function is like LWEs_ConvertTo_RLWE, but without using EvalTr.
	*/
	void LWEs_ConvertTo_RLWE_Without_EvalTr(const seal::SEALContext &context, const std::vector<LWECT> &src,
							seal::Ciphertext &des, const seal::GaloisKeys &galois_keys) const;


	/*
	n should be a power of 2, meaning that we want to reserve the
	iN/n-th coefficients, for 0 <= i < n.
	The result will be stored in c.
	*/
	void Reserve_Coefficients(const seal::SEALContext &context, seal::Ciphertext &c,
							const seal::GaloisKeys &galois_keys) const;
};

/*
The plaintext should be provided in both ntt form and non-ntt form
@idx: the index of the coefficient to be extracted
*/
void BFV_multiply_plain_then_extract(const seal::SEALContext &context, 
	seal::Ciphertext &ct, const seal::Plaintext &plain_non_ntt,
	const seal::Plaintext &plain_ntt, size_t idx = 0,
	seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool());

#endif