#include "types.hh"

using std::endl;

/**
 * Define << for a merkle node.
 *
 * @param      os    The ostream
 * @param[in]  mn    The merkle node
 *
 * @return     The string description of the node.
 */
std::ostream& operator << (std::ostream& os, const merkle_node& mn) {
    os << "hash:" << print_bytes(mn.hash.data(), HASH_SIZE) << endl
       << "height: " << (size_t) mn.height << endl
       << "index: " << mn.index << endl;
    return os;
}

/**
 * Comparison operator for two merkle nodes.
 *
 * a < b iff a will appear first in the tree update.
 *
 * @param[in]  a     A merkle node
 * @param[in]  b     A merkle node.
 *
 * @return     True if a < b, false otherwise.
 */
bool operator < (const merkle_node &a, const merkle_node &b) {
    int left_update_num = (1 + a.index) * (1 << a.height);
    int right_update_num = (1 + b.index) * (1 << b.height);
    if (left_update_num < right_update_num)
        return true;
    if (left_update_num == right_update_num && a.height < b.height)
        return true;
    return false;
}

/**
 * Combine two merkle nodes to one of the level above.
 *
 * @param[in]  a     Left child
 * @param[in]  b     Right child
 *
 * @return     Parent of a and b.
 */
merkle_node combine(merkle_node a, merkle_node b) {
    byte sha_input[2 * HASH_SIZE];
    std::copy(a.hash.begin(), a.hash.begin() + HASH_SIZE, sha_input);
    std::copy(b.hash.begin(), b.hash.begin() + HASH_SIZE, sha_input + HASH_SIZE);
    sha256(sha_input, 2 * HASH_SIZE, b.hash.data());
    b.index = b.index / 2;
    b.height++;
    return b;
}

/**
 * Calculate a leaf of the merkle tree.
 *
 * A PRG computes the secret key, then a one-time signature
 * public key is used as the leaf.
 *
 * @param      secret      This merkle node's seed
 * @param[in]  secret_len  The secret length
 * @param[in]  index       The index of the leaf
 *
 * @return     The public key at this leaf.
 */
merkle_node leafcalc(byte *secret, size_t secret_len, size_t index) {
    merkle_node leaf;
    WOTS_CLASS w = wotscalc(secret, secret_len, index);
    leaf.height = 0;
    leaf.index = index;
    leaf.hash = w.get_pk();
    return leaf;
}

/**
 * Compute a winternitz one-time public key at a specific index.
 *
 * @param      secret      The secret
 * @param[in]  secret_len  The secret length
 * @param[in]  index       The index
 *
 * @return     The WOTS_CLASS which has a public key available.
 */
WOTS_CLASS wotscalc(byte *secret, size_t secret_len, size_t index) {
    merkle_node leaf;
    PRG(secret, secret_len, leaf.hash.data(), HASH_SIZE, index);
    WOTS_CLASS w(leaf.hash);
    return w;
}
