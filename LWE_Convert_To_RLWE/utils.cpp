
#include "utils.h"


// the following code is modified from
// seal/util/rlwe.cpp#encrypt_zero_symmetric
// The symmetric RLWE encryption of m is given as (m + e - a*sk, a)
// The origin SEAL uses a general API encrypt_zero_symmetric() to generate (e
// - a*sk, a) first. Then the encryption of `m` is followed by addition `m + e
// - a*sk`
//
// Observation: we can perform the addition `m + e` first to save one NTT
// That is when `need_ntt=true` NTT(m) + NTT(e) is replaced by NTT(m + e)
void SymmetricRLWEEncrypt(const seal::SecretKey &sk,
                          const seal::SEALContext &context,
                          const seal::Plaintext &msg_non_ntt, bool need_ntt,
                          bool need_seed, seal::Ciphertext &out_ct)
{
  using namespace seal;
  using namespace seal::util;

  auto pool = MemoryManager::GetPool(mm_prof_opt::mm_force_thread_local, true);
  std::shared_ptr<UniformRandomGenerator> bootstrap_prng = nullptr;

  const RLWEPt& msg = msg_non_ntt;
  RLWECt& destination = out_ct;

  //auto parms_id = msg.parms_id();
  auto context_data = context.first_context_data();
  auto parms_id = context.first_parms_id();
  auto& parms = context_data->parms();
  auto& coeff_modulus = parms.coeff_modulus();
  size_t coeff_modulus_size = coeff_modulus.size();
  size_t coeff_count = parms.poly_modulus_degree();
  auto ntt_tables = context_data->small_ntt_tables();
  size_t encrypted_size = 2;

    // If a polynomial is too small to store UniformRandomGeneratorInfo,
    // it is best to just disable save_seed. Note that the size needed is
    // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
    // of an indicator word that indicates a seeded ciphertext.
  size_t poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);
  if (msg.coeff_count() != poly_uint64_count) {
      throw std::invalid_argument("msg coeff_count mismatch");
  }
  size_t prng_info_byte_count = static_cast<size_t>(
        UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
  size_t prng_info_uint64_count = divide_round_up(
        prng_info_byte_count, static_cast<size_t>(bytes_per_uint64));
  if (need_ntt && poly_uint64_count < prng_info_uint64_count + 1) {
      need_ntt = false;
  }

  destination.resize(context, parms_id, encrypted_size);
  destination.is_ntt_form() = need_ntt;
  destination.scale() = 1.0;
  destination.correction_factor() = 1;

    // Create an instance of a random number generator. We use this for
    // sampling a seed for a second PRNG used for sampling u (the seed can be
    // public information. This PRNG is also used for sampling the noise/error
    // below.
  if (!bootstrap_prng) {
      bootstrap_prng = parms.random_generator()->create();
  }

    // Sample a public seed for generating uniform randomness
    prng_seed_type public_prng_seed;
    bootstrap_prng->generate(
        prng_seed_byte_count,
        reinterpret_cast<seal_byte*>(public_prng_seed.data()));

    // Set up a new default PRNG for expanding u from the seed sampled above
    auto ciphertext_prng =
        UniformRandomGeneratorFactory::DefaultFactory()->create(
            public_prng_seed);

    // Generate ciphertext: (c[0], c[1]) = ([msg + e - a*s]_q, a) in BFV/CKKS
    uint64_t* c0 = destination.data();
    uint64_t* c1 = destination.data(1);

    // Sample a uniformly at random
    if (need_ntt || !need_seed) {
      // Sample the NTT form directly
      seal::util::sample_poly_uniform(ciphertext_prng, parms, c1);
    } else if (need_seed) {
      // Sample non-NTT form and store the seed
      seal::util::sample_poly_uniform(ciphertext_prng, parms, c1);
      for (size_t i = 0; i < coeff_modulus_size; i++) {
        // Transform the c1 into NTT representation
        seal::util::ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
      }
    }

    // Sample e <-- chi
    auto noise(allocate_poly(coeff_count, coeff_modulus_size, pool));
    SEAL_NOISE_SAMPLER(bootstrap_prng, parms, noise.get());

    // Calculate -(as + e) (mod q) and store in c[0] in BFV/CKKS
    for (size_t i = 0; i < coeff_modulus_size; i++) {
      seal::util::dyadic_product_coeffmod(sk.data().data() + i * coeff_count,
                              c1 + i * coeff_count, coeff_count,
                              coeff_modulus[i], c0 + i * coeff_count);
      if (need_ntt) {
        // Peform the addition m + e first
        // NOTE: lazy reduction here which will be obsorbed by
        // ntt_negacyclic_harvey
        std::transform(noise.get() + i * coeff_count,
                       noise.get() + i * coeff_count + coeff_count,
                       msg.data() + i * coeff_count,
                       noise.get() + i * coeff_count, std::plus<uint64_t>());

        // Then transform m + e to NTT form
        // noise <- m + e
        seal::util::ntt_negacyclic_harvey(noise.get() + i * coeff_count, ntt_tables[i]);
      } else {
        // c0 <- a*s - m
        seal::util::inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
        seal::util::sub_poly_coeffmod(c0 + i * coeff_count, msg.data() + i * coeff_count,
                          coeff_count, coeff_modulus[i], c0 + i * coeff_count);
      }

      // c0 <- noise - c0
      //    <- m + e - a*s   (need_ntt=true)
      //    <- e - (a*s - m) (need_ntt=false)
      sub_poly_coeffmod(noise.get() + i * coeff_count, c0 + i * coeff_count,
                        coeff_count, coeff_modulus[i], c0 + i * coeff_count);
    }

    if (!need_ntt && !need_seed) {
      for (size_t i = 0; i < coeff_modulus_size; i++) {
        // Transform the c1 into non-NTT representation
        inverse_ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
      }
    }

    if (need_seed) {
      UniformRandomGeneratorInfo prng_info = ciphertext_prng->info();

      // Write prng_info to destination.data(1) after an indicator word
      c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
      prng_info.save(reinterpret_cast<seal_byte*>(c1 + 1), prng_info_byte_count,
                     compr_mode_type::none);
    }
}




void SymmetricRLWEEncrypt(const seal::SecretKey& sk,
                          const seal::SEALContext& context,
                          const std::vector<seal::Plaintext> &msg_non_ntt, bool need_ntt,
                          bool need_seed, std::vector<seal::Ciphertext> &out_ct) {
  using namespace seal;
  using namespace seal::util;
  size_t n = msg_non_ntt.size();

  if (n == 0) {
    return;
  }

  auto pool = MemoryManager::GetPool(mm_prof_opt::mm_force_thread_local, true);
  std::shared_ptr<UniformRandomGenerator> bootstrap_prng = nullptr;

  for (size_t i = 0; i < n; ++i) {
    const RLWEPt& msg = msg_non_ntt[i];
    RLWECt& destination = out_ct[i];

    auto context_data = context.first_context_data();
    auto parms_id = context.first_parms_id();
    auto& parms = context_data->parms();
    auto& coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.poly_modulus_degree();
    auto ntt_tables = context_data->small_ntt_tables();
    size_t encrypted_size = 2;

    // If a polynomial is too small to store UniformRandomGeneratorInfo,
    // it is best to just disable save_seed. Note that the size needed is
    // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
    // of an indicator word that indicates a seeded ciphertext.
    size_t poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);
    if (msg.coeff_count() != poly_uint64_count) {
      throw std::invalid_argument("msg coeff_count mismatch");
    }
    size_t prng_info_byte_count = static_cast<size_t>(
        UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
    size_t prng_info_uint64_count = divide_round_up(
        prng_info_byte_count, static_cast<size_t>(bytes_per_uint64));
    if (need_ntt && poly_uint64_count < prng_info_uint64_count + 1) {
      need_ntt = false;
    }

    destination.resize(context, parms_id, encrypted_size);
    destination.is_ntt_form() = need_ntt;
    destination.scale() = 1.0;
    destination.correction_factor() = 1;

    // Create an instance of a random number generator. We use this for
    // sampling a seed for a second PRNG used for sampling u (the seed can be
    // public information. This PRNG is also used for sampling the noise/error
    // below.
    if (!bootstrap_prng) {
      bootstrap_prng = parms.random_generator()->create();
    }

    // Sample a public seed for generating uniform randomness
    prng_seed_type public_prng_seed;
    bootstrap_prng->generate(
        prng_seed_byte_count,
        reinterpret_cast<seal_byte*>(public_prng_seed.data()));

    // Set up a new default PRNG for expanding u from the seed sampled above
    auto ciphertext_prng =
        UniformRandomGeneratorFactory::DefaultFactory()->create(
            public_prng_seed);

    // Generate ciphertext: (c[0], c[1]) = ([msg + e - a*s]_q, a) in BFV/CKKS
    uint64_t* c0 = destination.data();
    uint64_t* c1 = destination.data(1);

    // Sample a uniformly at random
    if (need_ntt || !need_seed) {
      // Sample the NTT form directly
      sample_poly_uniform(ciphertext_prng, parms, c1);
    } else if (need_seed) {
      // Sample non-NTT form and store the seed
      sample_poly_uniform(ciphertext_prng, parms, c1);
      for (size_t i = 0; i < coeff_modulus_size; i++) {
        // Transform the c1 into NTT representation
        ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
      }
    }

    // Sample e <-- chi
    auto noise(allocate_poly(coeff_count, coeff_modulus_size, pool));
    SEAL_NOISE_SAMPLER(bootstrap_prng, parms, noise.get());

    // Calculate -(as + e) (mod q) and store in c[0] in BFV/CKKS
    for (size_t i = 0; i < coeff_modulus_size; i++) {
      dyadic_product_coeffmod(sk.data().data() + i * coeff_count,
                              c1 + i * coeff_count, coeff_count,
                              coeff_modulus[i], c0 + i * coeff_count);
      if (need_ntt) {
        // Peform the addition m + e first
        // NOTE: lazy reduction here which will be obsorbed by
        // ntt_negacyclic_harvey
        std::transform(noise.get() + i * coeff_count,
                       noise.get() + i * coeff_count + coeff_count,
                       msg.data() + i * coeff_count,
                       noise.get() + i * coeff_count, std::plus<uint64_t>());

        // Then transform m + e to NTT form
        // noise <- m + e
        ntt_negacyclic_harvey(noise.get() + i * coeff_count, ntt_tables[i]);
      } else {
        // c0 <- a*s - m
        inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
        sub_poly_coeffmod(c0 + i * coeff_count, msg.data() + i * coeff_count,
                          coeff_count, coeff_modulus[i], c0 + i * coeff_count);
      }

      // c0 <- noise - c0
      //    <- m + e - a*s   (need_ntt=true)
      //    <- e - (a*s - m) (need_ntt=false)
      sub_poly_coeffmod(noise.get() + i * coeff_count, c0 + i * coeff_count,
                        coeff_count, coeff_modulus[i], c0 + i * coeff_count);
    }

    if (!need_ntt && !need_seed) {
      for (size_t i = 0; i < coeff_modulus_size; i++) {
        // Transform the c1 into non-NTT representation
        inverse_ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
      }
    }

    if (need_seed) {
      UniformRandomGeneratorInfo prng_info = ciphertext_prng->info();

      // Write prng_info to destination.data(1) after an indicator word
      c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
      prng_info.save(reinterpret_cast<seal_byte*>(c1 + 1), prng_info_byte_count,
                     compr_mode_type::none);
    }
  }
}

void LWE_Key_ConvertTo_RLWE_Key(const seal::SEALContext& context, const lweSecretKey& LWE_key, seal::SecretKey& RLWE_key)
{
	const seal::EncryptionParameters& parms = context.key_context_data()->parms();
	const std::size_t num_coeff = parms.poly_modulus_degree();
	const std::vector<seal::Modulus>& moduli = parms.coeff_modulus();

	RLWE_key.data().parms_id() = seal::parms_id_zero;
	RLWE_key.data().resize(num_coeff * moduli.size());

	auto* sk_ptr = RLWE_key.data().data();

	for(unsigned int i=0; i<moduli.size(); ++i)
	{
		uint64_t mod = moduli[i].value();
    sk_ptr[i*num_coeff] = LWE_key.const_sk().data().data()[i*num_coeff] % mod;
		for(unsigned int j = 1; j<num_coeff; ++j)
		{
      
			seal::Plaintext::pt_coeff_type tmp = LWE_key.const_sk().data().data()[i*num_coeff + num_coeff - j] % mod;
			sk_ptr[i*num_coeff + j] = seal::util::negate_uint_mod(tmp, moduli[i]);
		}
	}

	const auto* ntt_tables = context.key_context_data()->small_ntt_tables();
	for (size_t l = 0; l < moduli.size(); l++, sk_ptr += num_coeff) 
	{
			seal::util::ntt_negacyclic_harvey(sk_ptr, ntt_tables[l]);
	}
	RLWE_key.data().parms_id() = context.key_context_data()->parms_id();
	
	return;
}

Timer::Timer()
{
  t_ = std::chrono::system_clock::now();
}


void Timer::StopWatch()
{
  auto tmp = std::chrono::system_clock::now();
  double dr = std::chrono::duration<double,std::micro>(tmp - t_).count();
  std::cout << dr << " microsecond\n";
  t_ = tmp;
}

void switch_key_inplace_ntt(const seal::SEALContext &context, seal::Ciphertext &encrypted, 
                        seal::util::ConstRNSIter target_iter, const KSwitchKeys &kswitch_keys, 
                        size_t kswitch_keys_index,
                        seal::MemoryPoolHandle pool)
{
    using namespace seal;
    using namespace seal::util;
        auto parms_id = encrypted.parms_id();
        auto context_data = context.get_context_data(parms_id);
        auto &parms = context_data->parms();
        auto key_context_data = context.key_context_data();
        auto &key_parms = key_context_data->parms();
        auto scheme = parms.scheme();

        // Extract encryption parameters.
        size_t coeff_count = parms.poly_modulus_degree();
        size_t decomp_modulus_size = parms.coeff_modulus().size();
        auto &key_modulus = key_parms.coeff_modulus();
        size_t key_modulus_size = key_modulus.size();
        size_t rns_modulus_size = decomp_modulus_size + 1;
        auto key_ntt_tables = iter(key_context_data->small_ntt_tables());
        auto modswitch_factors = key_context_data->rns_tool()->inv_q_last_mod_q();

        auto &key_vector = kswitch_keys.data()[kswitch_keys_index];
        size_t key_component_count = key_vector[0].data().size();

        // Create a copy of target_iter
        SEAL_ALLOCATE_GET_RNS_ITER(t_target, coeff_count, decomp_modulus_size, pool);
        set_uint(target_iter, decomp_modulus_size * coeff_count, t_target);

        inverse_ntt_negacyclic_harvey(t_target, decomp_modulus_size, key_ntt_tables);

        // Temporary result
        auto t_poly_prod(allocate_zero_poly_array(key_component_count, coeff_count, rns_modulus_size, pool));

        SEAL_ITERATE(iter(size_t(0)), rns_modulus_size, [&](auto I) {
            size_t key_index = (I == decomp_modulus_size ? key_modulus_size - 1 : I);

            // Product of two numbers is up to 60 + 60 = 120 bits, so we can sum up to 256 of them without reduction.
            size_t lazy_reduction_summand_bound = size_t(SEAL_MULTIPLY_ACCUMULATE_USER_MOD_MAX);
            size_t lazy_reduction_counter = lazy_reduction_summand_bound;

            // Allocate memory for a lazy accumulator (128-bit coefficients)
            auto t_poly_lazy(allocate_zero_poly_array(key_component_count, coeff_count, 2, pool));

            // Semantic misuse of PolyIter; this is really pointing to the data for a single RNS factor
            PolyIter accumulator_iter(t_poly_lazy.get(), 2, coeff_count);

            // Multiply with keys and perform lazy reduction on product's coefficients
            SEAL_ITERATE(iter(size_t(0)), decomp_modulus_size, [&](auto J) {
                SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);
                ConstCoeffIter t_operand;

                // RNS-NTT form exists in input
                if (I == J)
                {
                    t_operand = target_iter[J];
                }
                // Perform RNS-NTT conversion
                else
                {
                    // No need to perform RNS conversion (modular reduction)
                    if (key_modulus[J] <= key_modulus[key_index])
                    {
                        set_uint(t_target[J], coeff_count, t_ntt);
                    }
                    // Perform RNS conversion (modular reduction)
                    else
                    {
                        modulo_poly_coeffs(t_target[J], coeff_count, key_modulus[key_index], t_ntt);
                    }
                    // NTT conversion lazy outputs in [0, 4q)
                    ntt_negacyclic_harvey_lazy(t_ntt, key_ntt_tables[key_index]);
                    t_operand = t_ntt;
                }

                // Multiply with keys and modular accumulate products in a lazy fashion
                SEAL_ITERATE(iter(key_vector[J].data(), accumulator_iter), key_component_count, [&](auto K) {
                    if (!lazy_reduction_counter)
                    {
                        SEAL_ITERATE(iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                            unsigned long long qword[2]{ 0, 0 };
                            multiply_uint64(get<0>(L), get<1>(L), qword);

                            // Accumulate product of t_operand and t_key_acc to t_poly_lazy and reduce
                            add_uint128(qword, get<2>(L).ptr(), qword);
                            get<2>(L)[0] = barrett_reduce_128(qword, key_modulus[key_index]);
                            get<2>(L)[1] = 0;
                        });
                    }
                    else
                    {
                        // Same as above but no reduction
                        SEAL_ITERATE(iter(t_operand, get<0>(K)[key_index], get<1>(K)), coeff_count, [&](auto L) {
                            unsigned long long qword[2]{ 0, 0 };
                            multiply_uint64(get<0>(L), get<1>(L), qword);
                            add_uint128(qword, get<2>(L).ptr(), qword);
                            get<2>(L)[0] = qword[0];
                            get<2>(L)[1] = qword[1];
                        });
                    }
                });

                if (!--lazy_reduction_counter)
                {
                    lazy_reduction_counter = lazy_reduction_summand_bound;
                }
            });

            // PolyIter pointing to the destination t_poly_prod, shifted to the appropriate modulus
            PolyIter t_poly_prod_iter(t_poly_prod.get() + (I * coeff_count), coeff_count, rns_modulus_size);

            // Final modular reduction
            SEAL_ITERATE(iter(accumulator_iter, t_poly_prod_iter), key_component_count, [&](auto K) {
                if (lazy_reduction_counter == lazy_reduction_summand_bound)
                {
                    SEAL_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                        get<1>(L) = static_cast<uint64_t>(*get<0>(L));
                    });
                }
                else
                {
                    // Same as above except need to still do reduction
                    SEAL_ITERATE(iter(get<0>(K), *get<1>(K)), coeff_count, [&](auto L) {
                        get<1>(L) = barrett_reduce_128(get<0>(L).ptr(), key_modulus[key_index]);
                    });
                }
            });
        });
        // Accumulated products are now stored in t_poly_prod

        // Perform modulus switching with scaling
        PolyIter t_poly_prod_iter(t_poly_prod.get(), coeff_count, rns_modulus_size);
        SEAL_ITERATE(iter(encrypted, t_poly_prod_iter), key_component_count, [&](auto I) {
            
                // Lazy reduction; this needs to be then reduced mod qi
                CoeffIter t_last(get<1>(I)[decomp_modulus_size]);
                inverse_ntt_negacyclic_harvey_lazy(t_last, key_ntt_tables[key_modulus_size - 1]);

                // Add (p-1)/2 to change from flooring to rounding.
                uint64_t qk = key_modulus[key_modulus_size - 1].value();
                uint64_t qk_half = qk >> 1;
                SEAL_ITERATE(t_last, coeff_count, [&](auto &J) {
                    J = barrett_reduce_64(J + qk_half, key_modulus[key_modulus_size - 1]);
                });

                SEAL_ITERATE(iter(I, key_modulus, key_ntt_tables, modswitch_factors), decomp_modulus_size, [&](auto J) {
                    SEAL_ALLOCATE_GET_COEFF_ITER(t_ntt, coeff_count, pool);

                    // (ct mod 4qk) mod qi
                    uint64_t qi = get<1>(J).value();
                    if (qk > qi)
                    {
                        // This cannot be spared. NTT only tolerates input that is less than 4*modulus (i.e. qk <=4*qi).
                        modulo_poly_coeffs(t_last, coeff_count, get<1>(J), t_ntt);
                    }
                    else
                    {
                        set_uint(t_last, coeff_count, t_ntt);
                    }

                    // Lazy substraction, results in [0, 2*qi), since fix is in [0, qi].
                    uint64_t fix = qi - barrett_reduce_64(qk_half, get<1>(J));
                    SEAL_ITERATE(t_ntt, coeff_count, [fix](auto &K) { K += fix; });

                    uint64_t qi_lazy = qi << 1; // some multiples of qi
                    {
                        // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
                        ntt_negacyclic_harvey_lazy(t_ntt, get<2>(J));
#if SEAL_USER_MOD_BIT_COUNT_MAX > 60
                        // Reduce from [0, 4qi) to [0, 2qi)
                        SEAL_ITERATE(
                            t_ntt, coeff_count, [&](auto &K) { K -= SEAL_COND_SELECT(K >= qi_lazy, qi_lazy, 0); });
#else
                        // Since SEAL uses at most 60bit moduli, 8*qi < 2^63.
                        qi_lazy = qi << 2;
#endif
                    }
                    //inverse_ntt_negacyclic_harvey_lazy(get<0, 1>(J), get<2>(J));


                    // ((ct mod qi) - (ct mod qk)) mod qi with output in [0, 2 * qi_lazy)
                    SEAL_ITERATE(
                        iter(get<0, 1>(J), t_ntt), coeff_count, [&](auto K) { get<0>(K) += qi_lazy - get<1>(K); });

                    // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
                    multiply_poly_scalar_coeffmod(get<0, 1>(J), coeff_count, get<3>(J), get<1>(J), get<0, 1>(J));
                    add_poly_coeffmod(get<0, 1>(J), get<0, 0>(J), coeff_count, get<1>(J), get<0, 0>(J));
                });
        });
}

BaseDecompose::BaseDecompose(const std::uint64_t &oz, const seal::Modulus &oq)
:z(oz), q(oq)
{
  std::uint64_t qv = q.value();
  std::uint64_t z_power = 1;
  while(1 <= qv)
  {
    gz.push_back(z_power);
    z_power *= z;
    qv /= z;
  }
}

std::vector<std::uint64_t> BaseDecompose::Decompose(std::uint64_t x)
{
  std::uint64_t t = gz.size();
  std::vector<std::uint64_t> a(t);
  const std::uint64_t half_z = z >> 1;
  for(int i = t - 1; i >= 0; --i)
  {
    a[i] = x / gz[i];
    x -= a[i] * gz[i];
  }
  for(size_t i = 0; i < t; ++i)
  {
    if(a[i] > half_z)
    {
      a[i + 1] += 1;
      a[i] = q.value() - z + a[i];
    }
  }
  return a;
}