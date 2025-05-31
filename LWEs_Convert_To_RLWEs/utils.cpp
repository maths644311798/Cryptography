
#include "utils.h"



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
  t_ = std::chrono::steady_clock::now();
}


void Timer::StopWatch()
{
  auto tmp = std::chrono::steady_clock::now();
  double dr = std::chrono::duration<double,std::micro>(tmp - t_).count();
  std::cout << dr << " microsecond\n";
  t_ = tmp;
}

BaseDecompose::BaseDecompose(const seal::SEALContext &context, const std::uint64_t oz)
:z(oz), t(0)
{
  context_data = context.first_context_data();
  auto &parms = context_data->parms();
  size_t coeff_modulus_size = parms.coeff_modulus().size();
  const std::uint64_t *q = context_data->total_coeff_modulus();
  std::uint64_t quotient[coeff_modulus_size] = {0}, remainder[coeff_modulus_size] = {0};
  std::uint64_t numerator[coeff_modulus_size] = {0};
  std::copy_n(q, coeff_modulus_size, numerator);
  seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool();
  while(seal::util::get_significant_bit_count_uint(numerator, coeff_modulus_size) > 0)
  {
    seal::util::divide_uint(numerator, &z, coeff_modulus_size, quotient, remainder, pool);
    ++t;
    std::copy_n(quotient, coeff_modulus_size, numerator);
  }
}

std::vector<std::uint64_t> BaseDecompose::Decompose(const std::uint64_t *x, std::uint64_t uint64_count) const
{
  const std::uint64_t half_z = z >> 1;
  auto &parms = context_data->parms();
  auto &coeff_modulus = parms.coeff_modulus();
  size_t coeff_modulus_size = coeff_modulus.size();
  std::vector<std::uint64_t> a(t * coeff_modulus_size);
  seal::MemoryPoolHandle pool = seal::MemoryManager::GetPool();
  
  std::uint64_t quotient[coeff_modulus_size] = {0}, remainder[coeff_modulus_size] = {0};
  std::uint64_t numerator[coeff_modulus_size] = {0};
  std::copy_n(x, coeff_modulus_size, numerator);
  for(size_t i = 0; i < t; ++i)
  {
    seal::util::divide_uint(numerator, &z, coeff_modulus_size, quotient, remainder, pool);
    std::copy_n(quotient, coeff_modulus_size, numerator);
    a[i] = remainder[0];
  }

  for(size_t i = 0; i < t; ++i)
  {
    if(a[i] > half_z)
    {
#ifdef DEBUG
      if(i == t - 1) std::cout << "Overflow warning a[i] =" << a[i] << "\n";
#endif
      a[i + 1] += 1;
      std::uint64_t temp = z - a[i];
      for(size_t j = 0; j < coeff_modulus_size; ++j)
        a[i + j * t] = coeff_modulus[j].value() - temp;
    }
    else
    {
      for(size_t j = 1; j < coeff_modulus_size; ++j)
        a[i + j * t] = a[i];
    }
  }
  return a;
}
