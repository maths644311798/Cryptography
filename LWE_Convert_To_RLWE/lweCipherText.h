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

void Compute_N_inverse(const seal::SEALContext &context, std::vector<seal::Plaintext::pt_coeff_type> &N_inverse);

void Prepare_Galois(const seal::SEALContext &context, seal::KeyGenerator &keygen, seal::GaloisKeys &galois_keys);

//n should be a power of 2
void EvalTr(const seal::SEALContext &context, const LWECT &src,
			seal::Ciphertext &des, seal::GaloisKeys &galois_keys,
			const unsigned int n);

//Store an LWE ciphertext to the degree-0 term
void LWE_ConvertTo_RLWE(const seal::SEALContext &context, const LWECT& src,
						seal::Ciphertext &des, seal::GaloisKeys &galois_keys,
						const std::vector<seal::Plaintext::pt_coeff_type> &N_inverse);


//index_set is used to avoid copying lots of Ciphertexts
seal::Ciphertext PackLWEs(const seal::SEALContext &context, std::vector<unsigned long> index_set,
		std::vector<seal::Ciphertext> const &ct, seal::GaloisKeys &galois_keys);
//src.size should be a power of 2 and <= poly_degree
void LWEs_ConvertTo_RLWE(const seal::SEALContext &context, const std::vector<LWECT> &src,
						seal::Ciphertext &des, seal::GaloisKeys &galois_keys,
						const std::vector<seal::Plaintext::pt_coeff_type> &N_inverse);

#endif