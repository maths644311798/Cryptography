//GSW.h
#include <vector>
#include <seal/seal.h>
#include <iostream>
#include "utils.h"
/*
Ciphertexts are stored in seal::Ciphertext.
for a ciphertext in R_q^{2*m}, the memory stores the first row and then the second row
Reference: "Spiral: Fast, High-Rate Single-Server PIR via FHE Composition", Construction 2.14 
G_{2, z} = [1 z ... z^{t - 1} 1  0 0 ...       ]
           [0 0 ...           1 z ... z^{t - 1}]
*/
class GSW
{
public:

    GSW(const seal::SEALContext &context, const seal::SecretKey &sk, const std::size_t z = 2048);
    GSW(const seal::SEALContext &context, const std::size_t z = 2048)
    :GSW(context, seal::SecretKey(), z) {}

/*
For a message M in R_p,  a <- R_q^m, E <- \chi^{1 * m},

C = [ -sa + E ]   +  (q * M / p) G_{2, z}
    [    a    ]
SEAL BFV assumes the ciphertext (destination) is in non-NTT form.
GSW requires the ciphertexts to be in NTT form.
The encryption will allocate memory for the ciphertext.
*/
    void encrypt(const seal::Plaintext &plain, std::vector<std::uint64_t> &destination, bool is_ntt_form = true) const;
    void encrypt_zero(std::vector<std::uint64_t> &destination, bool is_ntt_form = true) const;

    void decrypt(const std::vector<std::uint64_t> &cipher, seal::Plaintext &plain) const;

    seal::SEALContext context_;
    seal::SecretKey sk_;
//Work in first_context_data
    std::size_t poly_modulus_degree_ = 0;
    std::vector<seal::Modulus> coeff_modulus_{};
    seal::Modulus plain_modulus_{};
    seal::parms_id_type parms_id_{seal::parms_id_zero};

    BaseDecompose BD;
    //m = 2 * t, t = floor(log_z(q)) + 1
    std::size_t m = 2;
};

std::ostream &operator<<(std::ostream &os, const GSW& gsw);