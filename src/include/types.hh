#pragma once
#include <array>
#include <vector>

#include <cereal/access.hpp>
#include <cereal/archives/binary.hpp>
#include <cereal/types/array.hpp>
#include <cereal/types/stack.hpp>
#include <cereal/types/vector.hpp>

#include "crypto_utils.hh"
#include "wots.hh"

class Treehash;

struct merkle_node {
    std::array<byte, HASH_SIZE> hash;
    unsigned char height;
    unsigned int index;

    template<class Archive>
    void serialize(Archive & archive) {
        archive(hash, height, index);
    }
};

struct signature_t {
    std::vector<merkle_node> auth_path;
    merkle_node leaf;
    ots_signature_t ots;

    template<class Archive>
    void serialize(Archive & archive) {
        archive(auth_path, leaf, ots);
    }
};

struct signer_info_t {
    std::array<byte, HASH_SIZE> secret_key;
    std::vector<merkle_node> auth_path;
    merkle_node retain;
    std::vector<Treehash> treehash_instances;
    std::vector<merkle_node> keep;
    std::vector<merkle_node> treehash_stack;
    merkle_node root;
    bool exhausted;

    template<class Archive>
    void serialize(Archive & archive) {
        archive(secret_key, auth_path, retain, treehash_instances, keep, exhausted, treehash_stack);
    }
};

struct keys_t {
    std::array<byte, HASH_SIZE> public_key;
    std::vector<signer_info_t> signer_states;
    unsigned int n_signers;
};

std::ostream& operator << (std::ostream& os, const merkle_node& mn);

bool operator < (const merkle_node &a, const merkle_node &b);

merkle_node combine(merkle_node a, merkle_node b);

merkle_node leafcalc(byte *secret, size_t secret_len, size_t index);

WOTS_CLASS wotscalc(byte *secret, size_t secret_len, size_t index);