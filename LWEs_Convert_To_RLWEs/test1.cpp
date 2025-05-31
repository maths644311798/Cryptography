
#include <iostream>
#include <sstream>
#include "seal/seal.h"
#include "lweCipherText.h"
#include "lweDecryptor.h"
#include "lweSecretKey.h"
#include "utils.h"
#include "HalfCipher.h"
#include "GSW.h"
#include <unistd.h>
#include <chrono>

using namespace std;
using namespace seal;
#define PLAIN_MODULUS 1073153

inline void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    case seal::scheme_type::bgv:
        scheme_name = "BGV";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    auto first_context_data = context.first_context_data();
    coeff_modulus = first_context_data->parms().coeff_modulus();
    coeff_modulus_size = coeff_modulus.size();
    std::cout << "First context data coefficient modulus size = " << coeff_modulus_size << "\n";

    auto cnt_data = context.key_context_data();
    std::cout << "context parms_id:\n";
    while(cnt_data)
    {
        auto par_id = cnt_data->parms_id();
        for(auto &x : par_id)
        {
            std::cout << x << " ";
        }
        std::cout << '\n';
        cnt_data = cnt_data->next_context_data();
    }

    std::cout << "\\" << std::endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
#define PRIME_60 (1152921504606830593ULL)
#define PRIME_49 (562949953216513ULL)
#define COEFF_MOD_ARR {PRIME_60, PRIME_49}


int main()
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    size_t num_coeff = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(COEFF_MOD_ARR);
    
    parms.set_plain_modulus(PLAIN_MODULUS);
    auto moduli = parms.coeff_modulus();
    size_t num_modulus = moduli.size();
    SEALContext context(parms,true, seal::sec_level_type::none);
    seal::MemoryPoolHandle pool =  seal::MemoryManager::GetPool();

    auto context_data_ptr = context.first_context_data();
    auto galois_tool = context_data_ptr->galois_tool();

    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    /*从文件导入密钥*/
    // std::ifstream file;file.open("SecretKey.txt", std::ios::binary);
    // SecretKey secret_key ;secret_key.load(context, file);
    /*keyGenerator生成密钥*/
    SecretKey secret_key;
    secret_key = keygen.secret_key();

    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key, secret_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    GSW gsw(context, secret_key, 0x2000);
    lweSecretKey lwe_key(secret_key, context);
    Packer packer(context, 4);
/*lwes to RLWE */
    SecretKey new_RLWE_key = seal::SecretKey(secret_key);
    
    LWE_Key_ConvertTo_RLWE_Key(context, lwe_key, new_RLWE_key);
    Encryptor encryptor_new(context, new_RLWE_key);
    Decryptor decryptor_new(context, new_RLWE_key);

    seal::KeyGenerator RLWE_key_generator(context, new_RLWE_key);
    
    seal::GaloisKeys galois_keys;
    Prepare_Galois(context, RLWE_key_generator, galois_keys);

    Plaintext pt1 = seal::Plaintext(poly_modulus_degree);////
    Plaintext pt2 = seal::Plaintext(poly_modulus_degree);
    Plaintext pt3 = seal::Plaintext(poly_modulus_degree);
    pt1[0] = 0x01;
    pt1[1] = 0x02;
    pt1[2] = 0x03;
    pt2[0] = 0x02;
    pt2[1024] = 0x01;

    Ciphertext ct(context), res_ct(context);
    Timer timer;
/*Verify BFV*/
    {
        encryptor.encrypt_symmetric(pt2, ct);

        timer.StopWatch();
        evaluator.multiply_plain(ct, pt1, res_ct);
        timer.StopWatch();

        decryptor.decrypt(res_ct, pt3);
        std::string temp_s = pt3.to_string();
        if(temp_s.length() > 100)
            cout << "Error: too long\n";
        else
            cout << "BFV Correct Result " << temp_s << '\n';
    }


/*Verify LWE*/
    {
        encryptor.encrypt_symmetric(pt1, ct);
        LWECT lwe_ct(context, ct, 0);
        lweDecryptor lwe_decrytor(context, lwe_key);
        uint64_t res_pt = lwe_decrytor.Decrypt(lwe_ct);
        std::cout << "BFV ciphertext in NTT ? " << ct.is_ntt_form() << "\n";
        std::cout << "LWE Correct Result " << res_pt << '\n';
    }

/* Verify Pack */
    {
        vector<LWECT> lwe_cts(4);
        vector<Ciphertext> BFV_cts(2);
        encryptor.encrypt_symmetric(pt1, BFV_cts[0]);
        encryptor.encrypt_symmetric(pt2, BFV_cts[1]);
        lwe_cts[0] = LWECT(context, BFV_cts[0], 0);
        lwe_cts[1] = LWECT(context, BFV_cts[0], 1);
        lwe_cts[2] = LWECT(context, BFV_cts[0], 2);
        lwe_cts[3] = LWECT(context, BFV_cts[1], 0);
        packer.LWEs_ConvertTo_RLWE(context, lwe_cts, res_ct, galois_keys);
        decryptor_new.decrypt(res_ct, pt3);
        std::cout << "Pack Correct Result ";
        for(size_t i = 0; i < 4; ++i) 
            std::cout << pt3[poly_modulus_degree / 4 * i] << " ";
        std::cout << "\n";
    }

/* Verify BFV_multiply_plain_then_extract */
    {
        encryptor.encrypt_symmetric(pt2, ct);
        seal::Plaintext pt_lift(pt1), plain_ntt(pt1);
        Plain_Lift_to_Rq(context_data_ptr, pt_lift);
        evaluator.transform_to_ntt_inplace(plain_ntt, context_data_ptr->parms_id(), pool);

        timer.StopWatch();
        LWECT lwe_ct =  BFV_multiply_plain_then_extract(context, ct, pt_lift, plain_ntt, 0, pool);
        timer.StopWatch();

        lweDecryptor lwe_decrytor(context, lwe_key);
        uint64_t res_pt = lwe_decrytor.Decrypt(lwe_ct);
        std::cout << "BFV_multiply_plain_then_extract result " << res_pt << "\n";
    }


/*Verify the BaseDecomposition
    cout << "BD.t = " << gsw.BD.t << "\n";
    for(uint64_t tv = moduli[0].value() - 1024; tv < moduli[0].value(); ++tv)
    {
        uint64_t x{0};
        vector<uint64_t> V = gsw.BD.Decompose(&tv, 1);
        for(int i = gsw.BD.t - 1; i >= 0; --i)
        {
            x = seal::util::multiply_add_uint_mod(x, gsw.BD.z, V[i], moduli[0]);
        }
        if(x != tv) cout << "wrong " << tv << "\n";
    }
*/

/*Verify GSW*/
/*
    cout << "Verify GSW\n";
    vector<uint64_t> vec_ct;
    {
        gsw.encrypt_zero(vec_ct, true);
        gsw.decrypt(vec_ct, pt3);
        if(!pt3.is_zero())
        {
            temp_s = pt3.to_string();
            cout << "GSW decrypt error. pt is not zero, but\n" << temp_s << "\n";
        }
    }

    {
        gsw.encrypt(pt1, vec_ct, true);
        gsw.decrypt(vec_ct, pt3);
        if(!std::equal(pt3.data(), pt3.data() + poly_modulus_degree, pt1.data(),
                       pt1.data() + poly_modulus_degree)) 
        {
            temp_s = pt3.to_string();
            cout << "GSW decrypt error. pt3 != pt1, pt3 = \n" << temp_s << "\n";
        }
    }
*/
    return 0;
}
