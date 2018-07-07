#include "types.hh"

bool verify(const std::array<byte, HASH_SIZE> &pk, const std::vector<byte> &message, const signature_t &signature);