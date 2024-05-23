
#include <iostream>
#include "seal/seal.h"
#include "lweCipherText.h"
#include "lweDecryptor.hpp"
#include "lweSecretKey.hpp"
#include "utils.h"

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




int main()
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    
    parms.set_plain_modulus(PLAIN_MODULUS);
    SEALContext context(parms,true, seal::sec_level_type::none);

    auto context_data = context.first_context_data();
    auto& coeff_modulus = parms.coeff_modulus();
    size_t first_coeff_modulus_size = coeff_modulus.size() - 1;

    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    /*从文件导入密钥*/
    // std::ifstream file;file.open("SecretKey.txt", std::ios::binary);
    // SecretKey secret_key ;secret_key.load(context, file);
    /*keyGenerator生成密钥*/
    SecretKey secret_key;
    secret_key = keygen.secret_key();


    Encryptor encryptor(context, secret_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

/* 为了做lwes到RLWE*/
    lweSecretKey lwe_key(secret_key, context);
    SecretKey new_RLWE_key = seal::SecretKey(secret_key);
    

    LWE_Key_ConvertTo_RLWE_Key(context, lwe_key, new_RLWE_key);//从LWE key到RLWE key
    Encryptor encryptor_new(context, new_RLWE_key);
    Decryptor decryptor_new(context, new_RLWE_key);
    seal::KeyGenerator RLWE_key_generator(context, new_RLWE_key);//定义密钥生成器
    seal::RelinKeys relin_keys;
    RLWE_key_generator.create_relin_keys(relin_keys);
    
    seal::GaloisKeys galois_keys;
    Prepare_Galois(context, RLWE_key_generator, galois_keys);
    Packer packer(context, 2);

    Plaintext pt1=seal::Plaintext(poly_modulus_degree);//////明文必须初始化
    Plaintext pt2=seal::Plaintext(poly_modulus_degree);
    Plaintext pt3=seal::Plaintext(poly_modulus_degree);
    pt1.set_zero();
    pt2.set_zero();
    pt3.set_zero();
        pt1[0] = 1;
    pt2[0] = 10;
    for(size_t i = 1; i < 40; ++i) 
        pt2[i] = i;
    pt2[poly_modulus_degree / 2] = 2;
    
    Ciphertext ct(context), ct1(context);
    encryptor.encrypt_symmetric(pt1, ct);
    cout << "   noise budget in freshly encrypted ct: " << decryptor.invariant_noise_budget(ct) << " bits"
         << endl;
    
 
    {
    vector<LWECT> lwe;
    LWECT ct_lwe(ct, 0, context), ct_lwe1(ct, 1, context);
    lwe.push_back(ct_lwe);
    lwe.push_back(ct_lwe1);
    packer.LWEs_ConvertTo_RLWE_Without_EvalTr(context, lwe, ct, galois_keys);
    }

    cout << "-------LWEs Convert To RLWE----------\n";
    decryptor_new.decrypt(ct,pt3);
    std::string temp_s = pt3.to_string();
    //if(temp_s.length() > 20)
    //    cout << "too long\n";
    //else
    //    cout << "Correct Result " << temp_s << '\n';


}