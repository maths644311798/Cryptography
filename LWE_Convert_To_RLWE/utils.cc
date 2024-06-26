
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

