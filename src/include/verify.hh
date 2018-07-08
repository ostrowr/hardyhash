#include "types.hh"

bool verify(const std::array<byte, HASH_SIZE> &pk, const std::vector<byte> &message, const signature_t &signature);
signature_t load_signature(std::string path);
std::array<byte, HASH_SIZE> load_public_key(std::string path);