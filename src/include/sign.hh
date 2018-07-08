#include <vector>
#include <string>

#include "types.hh"

signature_t sign(std::string state_path, const std::vector<byte> &message);
void write_signature(const signature_t &signature, std::string path);