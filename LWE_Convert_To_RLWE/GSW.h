//GSW.h
#include <seal/seal.h>
/*
Ciphertexts are stored in seal::Ciphertext.
for a ciphertext in R_q^{2*m}, the memory stores the first row and then the second row
Reference: "Spiral: Fast, High-Rate Single-Server PIR via FHE Composition", Construction 2.14 
*/
class GSW
{
public:

    GSW(const seal::SEALContext &context, seal::SecretKey sk);


    inline void encrypt(const seal::Plaintext &plain, seal::Ciphertext &destination) const
    {
            
    }

    seal::SEALContext context_;
    seal::SecretKey sk_;
    std::size_t poly_modulus_degree_ = 0;
    std::vector<seal::Modulus> coeff_modulus_{};
    seal::Modulus plain_modulus_{};
};