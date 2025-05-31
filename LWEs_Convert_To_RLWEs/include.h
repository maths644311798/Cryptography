#pragma once

#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using RLWESecretKey = seal::SecretKey;

using RLWEPublicKey = seal::PublicKey;

using KSwitchKeys = seal::KSwitchKeys;

using GaloisKeys = seal::GaloisKeys;

using RLWECt = seal::Ciphertext;

using RLWEPt = seal::Plaintext;