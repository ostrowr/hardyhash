#include <openssl/bn.h>

#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <functional>
#include <cassert>

#include "wots.hh"
#include "crypto_utils.hh"

using std::array;
using std::cerr;
using std::endl;
using std::make_pair;
using std::map;
using std::pair;
using std::vector;

/**
 * Constructs the WOTS object.
 *
 * This object should not be used directly; use one of its child classes instead.
 *
 * @param[in]  key_material  Bytes from which the secret key should be generated.
 * @param[in]  width         The width of the WOTS
 * @param[in]  depth         The depth of the WOTS.
 */
WOTS::WOTS(array<byte, HASH_SIZE> key_material, size_t width, size_t depth) {
    sha256(key_material.data(), key_material.size(), this->sk_seed.data());
    this->width = width;
    this->depth = depth;
    this->used = false;
}

/**
 * Constructs the object without a key.
 *
 * @param[in]  width  The width
 * @param[in]  depth  The depth
 */
WOTS::WOTS(size_t width, size_t depth) {
    this->width = width;
    this->depth = depth;
}

/**
 * Derive the secret key for this WOTS.
 *
 * @return     The whole secret key.
 */
vector<byte> WOTS::derive_sk() {
    vector<byte> sk(this->width * HASH_SIZE);
    PRG(this->sk_seed.data(), this->sk_seed.size(), sk.data(), sk.size(), 0);
    return sk;
}

/**
 * Apply a function f to an input n_iters times.
 *
 * @param[in]  base     The initial hash
 * @param[in]  n_iters  The number of times to apply the hash.
 *
 * @return     f^(n_iters)(base)
 */
array<byte, HASH_SIZE> WOTS::iter_f(array<byte, HASH_SIZE> base, size_t n_iters) {
    // TODO make f a part of the class, instead of defaulting to sha256
    for (size_t i=0; i < n_iters; i++) {
        array<byte, HASH_SIZE> next;
        sha256(base.data(), base.size(), next.data());
        base = next;
    }
    return base;
}

/**
 * Gets the public key.
 *
 * @return     The public key.
 */
array<byte, HASH_SIZE> WOTS::get_pk() {
    return this->pk;
}

/**
 * Derive the public key from the secret key.
 */
void BasicWOTS::derive_pk() {
    vector<byte> pk_uncompressed(this->width * HASH_SIZE);
    vector<byte> sk = this->derive_sk();
    for (size_t i=0; i < this->width; i++) {
        array<byte, HASH_SIZE> sk_part;
        copy(sk.begin() + i * HASH_SIZE, sk.begin() + (i + 1) * HASH_SIZE, sk_part.begin());
        array<byte, HASH_SIZE> pk_part = this->iter_f(sk_part, this->depth);
        copy(pk_part.begin(), pk_part.end(), pk_uncompressed.begin() + i * HASH_SIZE);
    }
    sha256(pk_uncompressed.data(), pk_uncompressed.size(), this->pk.data());
}

/**
 * Transform a message into a vector of length this->width.
 *
 * @param[in]  message  The message
 *
 * @return     A vector where every element is in the range [0, depth]
 */
vector<size_t> BasicWOTS::transform_message(vector<byte> message) {
    // assumes depth 3
    array<byte, 64> sha_output;

    // TODO concat random string to the end of message
    sha512(message.data(), message.size(), sha_output.data());

    vector<size_t> P(this->width);
    for (size_t i = 0; i < P.size(); i++) {
        byte curr = sha_output[i / 4];
        // read 2 bits at a time
        switch (i % 4) {
            case 0: P[i] = curr & (3);
                    break;
            case 1: P[i] = (curr & (3 << 2)) >> 2;
                    break;
            case 2: P[i] = (curr & (3 << 4)) >> 4;
                    break;
            case 3: P[i] = (curr & (3 << 6)) >> 6;
                    break;
        }
    }
    return P;
}

/**
 * Sign a message with the one-time signature.
 *
 * Invalidates the object so it can't be used to sign any more messages.
 *
 * @param[in]  message  The message to sign
 *
 * @return     The one-time signature.
 */
ots_signature_t BasicWOTS::sign(vector<byte> message) {
    if (this->used) {
        cerr << "Already signed using this keypair." << endl;
        exit(2);
    }
    this->used = true;  // render this object useless
    vector<size_t> P = this->transform_message(message);
    ots_signature_t sig(P.size());
    vector<byte> sk = this->derive_sk();
    for (size_t i = 0; i < P.size(); i++) {
        array<byte, HASH_SIZE> sk_part;
        copy(sk.begin() + i * HASH_SIZE, sk.begin() + (i + 1) * HASH_SIZE, sk_part.begin());
        array<byte, HASH_SIZE> signature_part = iter_f(sk_part, P[i]);
        sig[i] = signature_part;
    }
    return sig;
}

/**
 * Verify a pk, message, signature triplet.
 *
 * @param[in]  pk         The OTS public key.
 * @param[in]  message    The message
 * @param[in]  signature  The signature
 *
 * @return     True if it verifies correctly, false otherwise.
 */
bool BasicWOTS::verify(array<byte, HASH_SIZE> pk, vector<byte> message, ots_signature_t signature) {
    vector<size_t> P = this->transform_message(message);
    vector<byte> pk_uncompressed(this->width * HASH_SIZE);

    for (size_t i=0; i < P.size(); i++) {
        array<byte, HASH_SIZE> pk_part = this->iter_f(signature[i], this->depth - P[i]);
        copy(pk_part.begin(), pk_part.end(), pk_uncompressed.begin() + i * HASH_SIZE);
    }
    array<byte, HASH_SIZE> pk_test;
    sha256(pk_uncompressed.data(), pk_uncompressed.size(), pk_test.data());
    return pk_test == pk;
}


/// FIXED WEIGHT UTILS (TODO move to a different file)

/**
 * Builds a cache of the number of fixed-weight integer
 * compositions. The cache maps (w, n) to the number of integer
 * compositions of w into n parts given that every part is in the range
 * [0, d].
 *
 * @param[in]  w     The weight of the signature
 * @param[in]  n     The width of the signature
 * @param[in]  d     The depth of the signature.
 *
 * @return     The counts cache.
 */
map<pair<int, int>, BIGNUM*> build_counts_cache(int w, int n, int d) {
    map<pair<int, int>, BIGNUM*> cache;
    BIGNUM *zero = BN_new();
    BIGNUM *one = BN_new();
    BN_one(one);
    cache[make_pair(0, 0)] = one;
    std::function<BIGNUM*(int, int)> build_cache_rec = [&] (int w, int n) {
        if (w < 0 || n < 0) {
            return zero;
        }
        pair<int, int> params = make_pair(w, n);
        auto it = cache.find(params);
        if (it != cache.end()) {
            return it->second;
        }
        BIGNUM *total = BN_new();
        for (int i = 0; i <= d; i++) {
            BN_add(total, total, build_cache_rec(w - i, n - 1));
        }
        cache[params] = total;
        return total;
    };
    build_cache_rec(w, n);
    BN_free(zero);
    return cache;
}

/**
 * Free the counts cache generated by build_counts_cache.
 *
 * @param      counts  The counts cache.
 */
void free_cache(map<pair<int, int>, BIGNUM*> &counts) {
    for (auto &entry : counts) {
        BN_free(entry.second);
        entry.second = NULL;
    }
}


/**
 * Map a restricted integer composition to its index in a lexicographic
 * ordering of all valid compositions defined by the counts cache.
 *
 * @param[in]  composition  The composition
 * @param      counts       The counts cache
 *
 * @return     The lexicographic index of the composition.
 */
BIGNUM *composition_to_index(vector<size_t> composition, map<pair<int, int>, BIGNUM*> &counts) {
    BIGNUM *num_below = BN_new();
    size_t weight = 0;
    for (size_t &elem : composition) weight += elem;
    assert(weight == 241);
    size_t n = composition.size();
    for (auto &d : composition) {
        for (size_t i = 0; i < d; i++) {
            BN_add(num_below, num_below, counts[{weight - i, n - 1}]);
        }
        weight -= d;
        n -= 1;
    }
    return num_below;
}

/**
 * Map an integer to a single integer composition.
 *
 * Note that the integer must be less than the number of possible compositions.
 *
 * @param[in]  w       The weight of the compositions
 * @param[in]  n       The width of the compositions
 * @param[in]  d       The max depth of each part of the compositions
 * @param      index   The integer to map to a composition
 * @param      counts  The counts cache.
 *
 * @return     A restricted integer composition of weight w, width n and depth max d.
 */
vector<size_t> index_to_composition(int w, int n, int d, BIGNUM *index, map<pair<int, int>, BIGNUM*> &counts) {
    /*
    // index 0
    vector<size_t> minimum = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
    // index 1
    vector<size_t> first = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
    // index 2
    vector<size_t> second = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
    // index 3
    vector<size_t> third = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
    // max index (counts_cache[{241, 134}] - 1)
    vector<size_t> maximum = {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    for (auto test : {minimum, first, second, third, maximum}) {
        assert(index_to_composition(241, 134, 3, composition_to_index(test, counts), counts) == test);s
    }
    */
    vector<size_t> composition(n);
    for (size_t i = 0; i < composition.size(); i++) {
        for (int depth = 0; depth <= d; depth++) {
            BN_sub(index, index, counts[{w - depth, n - 1}]);
            if (BN_is_negative(index)) {
                BN_add(index, index, counts[{w - depth, n - 1}]);
                composition[i] = depth;
                break;
            }
        }
        n--;
        w -= composition[i];
    }
    return composition;
}


/**
 * Transform a message into a restricted integer composition.
 *
 * @param[in]  message  The message
 *
 * @return     A restricted integer composition of the WeightConstant,
 *             with width parts and each part in [0, depth].
 */
vector<size_t> FixedWeightWOTS::transform_message(vector<byte> message) {
    // implements an injection from integers in [0, 2^256-1]
    // to restricted integer compositions of this->WeightConstant,
    // where each part is in [0, this->depth] and there are exactly
    // this->width parts.
    array<byte, HASH_SIZE> sha_output;

    // TODO concat random string to the end of message
    sha256(message.data(), message.size(), sha_output.data());
    BIGNUM *hash_as_int = NULL;
    BN_hex2bn(&hash_as_int, print_bytes(sha_output.data(), sha_output.size()).c_str());

    // todo maybe calculate once and read in file. It doesn't take that long,
    // though, so not such a big deal.
    map<pair<int, int>, BIGNUM*> counts = build_counts_cache(this->WeightConstant, this->width, this->depth);

    // TODO prove that just the first 2^256 compositions are still misuse resistant
    vector<size_t> composition = index_to_composition(this->WeightConstant, this->width,
                                                      this->depth, hash_as_int, counts);
    BN_free(hash_as_int);
    free_cache(counts);
    return composition;
}
