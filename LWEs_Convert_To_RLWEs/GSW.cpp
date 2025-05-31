//GSW.cpp
#include "GSW.h"
#include <seal/util/scalingvariant.h>

#undef DEBUG

GSW::GSW(const seal::SEALContext &context, const seal::SecretKey &sk, const std::size_t z)
:context_(context) ,sk_(sk), BD(context, z), m(BD.t << 1)
{
    auto &parms = context_.first_context_data()->parms();
    coeff_modulus_ = parms.coeff_modulus();
    poly_modulus_degree_ = parms.poly_modulus_degree();
    plain_modulus_ = parms.plain_modulus();
    parms_id_ = context.first_context_data()->parms_id();
}

void GSW::encrypt(const seal::Plaintext &plain, std::vector<std::uint64_t> &destination, bool is_ntt_form) const
{
    std::size_t coeff_modulus_size = coeff_modulus_.size();
    size_t poly_uint64_count = seal::util::mul_safe(poly_modulus_degree_, coeff_modulus_size);
    seal::Plaintext plain_q(poly_uint64_count, poly_uint64_count);
    seal::util::multiply_add_plain_with_scaling_variant(plain, *BD.context_data, 
                                                seal::util::RNSIter(plain_q.data(), poly_modulus_degree_));
    encrypt_zero(destination, false);
#ifdef DEBUG
    std::cout << "encrypt_zero success\n";
#endif
    std::vector<std::uint64_t> tmp(poly_uint64_count);
    std::copy_n(plain_q.data(), poly_uint64_count, tmp.data());
    for(std::size_t i = 0; i < BD.t; ++i)
    {
        std::uint64_t *c_up = destination.data() + i * poly_uint64_count; 
        std::uint64_t *c_down = c_up + (m + BD.t) * poly_uint64_count;
        seal::util::add_poly_coeffmod(seal::util::ConstRNSIter(c_up, poly_modulus_degree_), 
                                    seal::util::ConstRNSIter(tmp.data(), poly_modulus_degree_), 
                                    coeff_modulus_size, coeff_modulus_.data(), 
                                    seal::util::RNSIter(c_up, poly_modulus_degree_));
        seal::util::add_poly_coeffmod(seal::util::ConstRNSIter(c_down, poly_modulus_degree_), 
                                    seal::util::ConstRNSIter(tmp.data(), poly_modulus_degree_), 
                                    coeff_modulus_size, coeff_modulus_.data(), 
                                    seal::util::RNSIter(c_down, poly_modulus_degree_));
        if(i == BD.t - 1) break;
        for(std::size_t j = 0; j < coeff_modulus_size; ++j)
        {
            seal::util::multiply_poly_scalar_coeffmod(tmp.data() + j * poly_modulus_degree_, 
                                                    poly_modulus_degree_, BD.z, coeff_modulus_[j], 
                                                    tmp.data() + j * poly_modulus_degree_);
        }
    }
    if(is_ntt_form)
    {
        for(std::size_t i = 0; i < (m << 1); ++i)
        {
            auto ntt_tables = iter(BD.context_data->small_ntt_tables());
            seal::util::ntt_negacyclic_harvey(
                seal::util::RNSIter(destination.data() + i * poly_uint64_count, poly_modulus_degree_), 
                coeff_modulus_size, ntt_tables);
        }
    }
}

void GSW::encrypt_zero(std::vector<std::uint64_t> &destination, bool is_ntt_form) const
{
    seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_new, true);
    auto &context_data = *context_.get_context_data(parms_id_);
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    auto &plain_modulus = parms.plain_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    auto ntt_tables = context_data.small_ntt_tables();

    size_t poly_uint64_count = seal::util::mul_safe(poly_modulus_degree_, coeff_modulus_size);

    destination.resize((m << 1) * poly_uint64_count);

    auto bootstrap_prng = parms.random_generator()->create();
    seal::prng_seed_type public_prng_seed;
    bootstrap_prng->generate(seal::prng_seed_byte_count, reinterpret_cast<seal::seal_byte *>(public_prng_seed.data()));
    auto ciphertext_prng = seal::UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed);

    uint64_t *c0 = destination.data();
    uint64_t *c1 = destination.data() + m * poly_uint64_count;
    for(std::size_t j = 0; j < m; ++j)
    {
//c1 is uniform in NTT form and non-NTT form, the result of the sampling should be regarded in NTT form
        seal::util::sample_poly_uniform(ciphertext_prng, parms, c1);

        auto noise(seal::util::allocate_poly(poly_modulus_degree_, coeff_modulus_size, pool));
        std::uint64_t *noise_ptr = noise.get();
        seal::RandomToStandardAdapter engine(bootstrap_prng);
        std::normal_distribution<double> normal_(0, seal::util::global_variables::noise_standard_deviation);
        for(std::size_t i = 0; i < coeff_modulus_size; ++i)
            for(std::size_t k = 0; k < poly_modulus_degree_; ++k)
        {
            int64_t value = static_cast<int64_t>(normal_(engine));
#ifdef DEBUG
            if(value >= 20 || value <= -20)
                cout << "Noise larger than 20\n";
#endif
            uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(value < 0));
            noise_ptr[i * poly_modulus_degree_ + k] = static_cast<uint64_t>(value) + (flag & coeff_modulus_[i].value());
        }

        //Calculate -(as+ e) (mod q) and store in c[0]
        for (size_t i = 0; i < coeff_modulus_size; i++)
        {
             seal::util::dyadic_product_coeffmod(sk_.data().data() + i * poly_modulus_degree_, 
                                    c1 + i * poly_modulus_degree_, poly_modulus_degree_, coeff_modulus_[i],
                                    c0 + i * poly_modulus_degree_);
            if (is_ntt_form)
            {
                seal::util::ntt_negacyclic_harvey(noise_ptr + i * poly_modulus_degree_, ntt_tables[i]);
            }
            else
            {
                seal::util::inverse_ntt_negacyclic_harvey(c0 + i * poly_modulus_degree_, ntt_tables[i]);
            }
            seal::util::add_poly_coeffmod(noise_ptr + i * poly_modulus_degree_, c0 + i * poly_modulus_degree_, 
                                        poly_modulus_degree_, coeff_modulus[i], c0 + i * poly_modulus_degree_);
            seal::util::negate_poly_coeffmod(c0 + i * poly_modulus_degree_, poly_modulus_degree_, 
                                            coeff_modulus[i], c0 + i * poly_modulus_degree_);
        }
        if (!is_ntt_form)
        {
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                seal::util::inverse_ntt_negacyclic_harvey(c1 + i * poly_modulus_degree_, ntt_tables[i]);
            }
        }
        c0 = c0 + poly_uint64_count;
        c1 = c1 + poly_uint64_count;
    }
}

void GSW::decrypt(const std::vector<std::uint64_t> &cipher, seal::Plaintext &plain) const
{
    seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_new, true);
    auto &parms = BD.context_data->parms();
    size_t coeff_modulus_size = coeff_modulus_.size();
    size_t poly_uint64_count = seal::util::mul_safe(poly_modulus_degree_, coeff_modulus_size);
    auto ntt_tables = BD.context_data->small_ntt_tables();

    std::vector<uint64_t> tmp_dest_modq(poly_uint64_count);
    //dot_product_ct_sk
    const std::uint64_t *sk_ptr = sk_.data().data();
    const std::uint64_t *c0 = cipher.data(), *c1 = c0 + m * poly_uint64_count;
    for(size_t i = 0; i < coeff_modulus_size; ++i)
    {
        seal::util::dyadic_product_coeffmod(c1 + i * poly_modulus_degree_, sk_ptr + i * poly_modulus_degree_, 
                                        poly_modulus_degree_, coeff_modulus_[i], 
                                        tmp_dest_modq.data() + i * poly_modulus_degree_);
        seal::util::add_poly_coeffmod(tmp_dest_modq.data() + i * poly_modulus_degree_, c0 + i * poly_modulus_degree_, 
                        poly_modulus_degree_, coeff_modulus_[i], tmp_dest_modq.data() + i * poly_modulus_degree_);
        //Back to non-NTT form
        seal::util::inverse_ntt_negacyclic_harvey(tmp_dest_modq.data() + i * poly_modulus_degree_, ntt_tables[i]);
    }

    plain.parms_id() = seal::parms_id_zero;
    plain.resize(poly_modulus_degree_);

    BD.context_data->rns_tool()->decrypt_scale_and_round(
                                            seal::util::ConstRNSIter(tmp_dest_modq.data(), poly_modulus_degree_), 
                                            plain.data(), pool);
}

void GSW::encode(const std::vector<std::uint64_t> &plain_q, std::vector<std::uint64_t> &destination, 
                bool is_ntt_form) const
{
    std::size_t coeff_modulus_size = coeff_modulus_.size();
    size_t poly_uint64_count = seal::util::mul_safe(poly_modulus_degree_, coeff_modulus_size);
    encrypt_zero(destination, false);
#ifdef DEBUG
    std::cout << "encrypt_zero success\n";
    if(plain_q.size() != poly_uint64_count)
        std::cout << "Error plain_q.size = " << plain_q.size() << "\n";
#endif
    std::vector<std::uint64_t> tmp(poly_uint64_count);
    std::copy_n(plain_q.data(), poly_uint64_count, tmp.data());
    for(std::size_t i = 0; i < BD.t; ++i)
    {
        std::uint64_t *c_up = destination.data() + i * poly_uint64_count; 
        std::uint64_t *c_down = c_up + (m + BD.t) * poly_uint64_count;
        seal::util::add_poly_coeffmod(seal::util::ConstRNSIter(c_up, poly_modulus_degree_), 
                                    seal::util::ConstRNSIter(tmp.data(), poly_modulus_degree_), 
                                    coeff_modulus_size, coeff_modulus_.data(), 
                                    seal::util::RNSIter(c_up, poly_modulus_degree_));
        seal::util::add_poly_coeffmod(seal::util::ConstRNSIter(c_down, poly_modulus_degree_), 
                                    seal::util::ConstRNSIter(tmp.data(), poly_modulus_degree_), 
                                    coeff_modulus_size, coeff_modulus_.data(), 
                                    seal::util::RNSIter(c_down, poly_modulus_degree_));
        if(i == BD.t - 1) break;
        for(std::size_t j = 0; j < coeff_modulus_size; ++j)
        {
            seal::util::multiply_poly_scalar_coeffmod(tmp.data() + j * poly_modulus_degree_, 
                                                    poly_modulus_degree_, BD.z, coeff_modulus_[j], 
                                                    tmp.data() + j * poly_modulus_degree_);
        }
    }
    if(is_ntt_form)
    {
        for(std::size_t i = 0; i < (m << 1); ++i)
        {
            auto ntt_tables = iter(BD.context_data->small_ntt_tables());
            seal::util::ntt_negacyclic_harvey(
                seal::util::RNSIter(destination.data() + i * poly_uint64_count, poly_modulus_degree_), 
                coeff_modulus_size, ntt_tables);
        }
    }
}


void GSW::MultiplyBFV(const std::vector<std::uint64_t> &GSW_cipher, const seal::Ciphertext &BFV_cipher, 
                            seal::Ciphertext &destination) const
{
    seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_new, true);
    size_t coeff_modulus_size = coeff_modulus_.size();
    size_t poly_uint64_count = seal::util::mul_safe(poly_modulus_degree_, coeff_modulus_size);
    auto rns_tool = BD.context_data->rns_tool();
    auto ntt_tables = BD.context_data->small_ntt_tables();
    std::vector<std::uint64_t> temp(BD.t * coeff_modulus_size);
    std::vector<std::uint64_t> G_inverse_res(m * poly_uint64_count);

    destination = BFV_cipher;
#ifdef DEBUG
    if(rns_tool->base_q()->size() != coeff_modulus_size)
        std::cout << "Error: rns size = " << rns_tool->base_q()->size() << " != " << coeff_modulus_size << "\n";
#endif
    for(size_t i = 0; i < 2; ++i)
    {
        std::uint64_t *c = destination.data(i);
        rns_tool->base_q()->compose_array(c, poly_modulus_degree_, pool);
        for(size_t j = 0; j < poly_modulus_degree_; ++j)
        {
            temp = BD.Decompose(c + j * coeff_modulus_size, coeff_modulus_size);
            for(size_t mi = 0; mi < coeff_modulus_size; ++mi)
                for(size_t ti = 0; ti < BD.t; ++ti)
                    G_inverse_res[(i * BD.t + ti) * poly_uint64_count + mi * poly_modulus_degree_ + j] =
                        temp[mi * BD.t + ti];
        }
    }
    temp.resize(poly_uint64_count);
    for(auto p = destination.data(); p != destination.data() + 2 * poly_uint64_count; ++p)
        *p = 0;
    for(size_t i = 0; i < m; ++i)
    {
        seal::util::ntt_negacyclic_harvey(
            seal::util::RNSIter(G_inverse_res.data() + i * poly_uint64_count, poly_modulus_degree_), 
            coeff_modulus_size, ntt_tables);
        std::uint64_t *c = destination.data();
        seal::util::dyadic_product_coeffmod(
            seal::util::ConstRNSIter(GSW_cipher.data() + i * poly_uint64_count, poly_modulus_degree_),
            seal::util::ConstRNSIter(G_inverse_res.data() + i * poly_uint64_count, poly_modulus_degree_),
            coeff_modulus_size, coeff_modulus_.data(), seal::util::RNSIter(temp.data(), poly_modulus_degree_));
        seal::util::add_poly_coeffmod(seal::util::ConstRNSIter(temp.data(), poly_modulus_degree_),
            seal::util::ConstRNSIter(c, poly_modulus_degree_), coeff_modulus_size, coeff_modulus_.data(),
            seal::util::RNSIter(c, poly_modulus_degree_));
        c = destination.data(1);
        seal::util::dyadic_product_coeffmod(
            seal::util::ConstRNSIter(GSW_cipher.data() + (m + i) * poly_uint64_count, poly_modulus_degree_),
            seal::util::ConstRNSIter(G_inverse_res.data() + i * poly_uint64_count, poly_modulus_degree_),
            coeff_modulus_size, coeff_modulus_.data(), seal::util::RNSIter(temp.data(), poly_modulus_degree_));
        seal::util::add_poly_coeffmod(seal::util::ConstRNSIter(temp.data(), poly_modulus_degree_),
            seal::util::ConstRNSIter(c, poly_modulus_degree_), coeff_modulus_size, coeff_modulus_.data(),
            seal::util::RNSIter(c, poly_modulus_degree_));
    }
    seal::util::inverse_ntt_negacyclic_harvey(
        seal::util::RNSIter(destination.data(), poly_modulus_degree_), coeff_modulus_size, ntt_tables);
    seal::util::inverse_ntt_negacyclic_harvey(
        seal::util::RNSIter(destination.data(1), poly_modulus_degree_), coeff_modulus_size, ntt_tables);
}

std::ostream &operator<<(std::ostream &os, const GSW& gsw)
{
    os << "GSW parameter:\n";
    os << "m = " << gsw.m << "\n";
    return os;
}
