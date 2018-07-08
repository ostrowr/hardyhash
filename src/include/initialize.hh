#include "treehash.hh"

keys_t *initialize(size_t lg_n_signers, size_t lg_messages_per_signer, const byte *randomness, size_t randomness_size);
void write_signer_states(keys_t *k, std::string output_dir);