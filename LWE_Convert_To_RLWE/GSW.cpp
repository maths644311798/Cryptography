//GSW.cpp
#include "GSW.h"

GSW::GSW(const seal::SEALContext &context, seal::SecretKey sk)
:context_(context) ,sk_(sk)
{
    auto &parms = context_.key_context_data()->parms();
    coeff_modulus_ = parms.coeff_modulus();
    poly_modulus_degree_ = parms.poly_modulus_degree();
    plain_modulus_ = parms.plain_modulus();
}