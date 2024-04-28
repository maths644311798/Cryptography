#ifndef LWECIPHERTEXT_H
#define LWECIPHERTEXT_H


#include <cmath>
#include <memory>
#include "include.h"
#include "seal/util/polyarithsmallmod.h"

class LWECT {
private:
	seal::Plaintext ct1; // ct1
	std::vector<uint64_t> ct0; // ct0, if modulus switch is applied, only one modulus is left
	std::size_t poly_modulus_degree_{ 0 }; // length of every single polynomial

public:
    // coeff_index represents the index to be extracted
	LWECT() = default;
    LWECT(const seal::Ciphertext& RLWECT, const std::size_t coeff_index,
	const seal::SEALContext& context);
    // Some useful help functions
	inline const std::size_t poly_modulus_degree() const { return poly_modulus_degree_; }
	inline seal::parms_id_type parms_id() const { return ct1.parms_id(); }
	inline const double scale() { return ct1.scale(); }
	inline std::vector<uint64_t>& get_ct0() { return ct0; }
	inline const std::vector<uint64_t>& get_ct0() const { return ct0; }
	inline const seal::Plaintext& get_ct1() const { return ct1; }
};

void Prepare_Galois(const seal::SEALContext &context, seal::KeyGenerator &keygen, seal::GaloisKeys &galois_keys);

//n should be a power of 2
void EvalTr(const seal::SEALContext &context, const LWECT &src,
				seal::Ciphertext &des, seal::GaloisKeys &galois_keys,
				const unsigned int n);

class Packer
{
public:

	std::vector<seal::Plaintext::pt_coeff_type> N_inverse;
	// the inverse of N/n mod q
	std::vector<seal::Plaintext::pt_coeff_type> N_over_n_inverse;
	std::vector<seal::Plaintext::pt_coeff_type> n_inverse;
	size_t n_;

	Packer() = default;

	/*
	n should be a power of 2, meaning that we want to reserve the
	iN/n-th coefficients, for 0 <= i < n.
	*/
	Packer(const seal::SEALContext &context, const size_t &n);

	void Compute_inverses(const seal::SEALContext &context);


	//Store an LWE ciphertext to the degree-0 term
	void LWE_ConvertTo_RLWE(const seal::SEALContext &context, const LWECT& src,
							seal::Ciphertext &des, const seal::GaloisKeys &galois_keys) const;


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
#endif