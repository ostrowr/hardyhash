#include "verify.hh"

#include <fstream>
#include <cassert>

#include "types.hh"

using std::array;
using std::cout;
using std::endl;
using std::string;
using std::vector;

/**
 * Loads a signature from a signature file
 *
 * @param[in]  path  The path to the signature file
 *
 * @return     The signature
 */
signature_t load_signature(string path) {
    std::ifstream is(path);
    cereal::BinaryInputArchive iarchive(is);
    signature_t signature;
    iarchive(signature);
    return signature;
}

/**
 * Loads a public key.
 *
 * @param[in]  path  The path to the public key
 *
 * @return     The public key.
 */
array<byte, HASH_SIZE> load_public_key(string path) {
    std::ifstream is(path);
    cereal::BinaryInputArchive iarchive(is);
    array<byte, HASH_SIZE> pk;
    iarchive(pk);
    return pk;
}

/**
 * Verify that a leaf of the merkle tree is correct.
 *
 * Hash against its authentication path up to the root, which
 * should match the public key.
 *
 * @param[in]  signature  The signature, including the authentication path.
 * @param[in]  pk         The public key.
 *
 * @return     True if the public key is the correct leaf node in the merkle tree, false otherwise.
 */
bool verify_leaf(const signature_t &signature, const array<byte, HASH_SIZE> &pk) {
    merkle_node leaf = signature.leaf;
    byte sha_input[2 * HASH_SIZE];
    for (merkle_node mn : signature.auth_path) {
        bool auth_is_right_node = mn.index % 2;
        std::copy(leaf.hash.begin(), leaf.hash.begin() + HASH_SIZE, sha_input + HASH_SIZE * (1 - auth_is_right_node));
        std::copy(mn.hash.begin(), mn.hash.begin() + HASH_SIZE, sha_input + HASH_SIZE * auth_is_right_node);
        sha256(sha_input, 2 * HASH_SIZE, leaf.hash.data());
    }
    return leaf.hash == pk;
}

/**
 * Verify the one-time signature.
 *
 * @param[in]  signature  The signature
 * @param[in]  message    The message
 *
 * @return     True if the OTS verifies, false otherwise.
 */
bool verify_ots(const signature_t &signature, const vector<byte> &message) {
    WOTS_CLASS w;
    return w.verify(signature.leaf.hash, message, signature.ots);
}

/**
 * Verify both the OTS and the key for the OTS.
 *
 * @param[in]  pk         The public key
 * @param[in]  message    The message
 * @param[in]  signature  The signature
 *
 * @return     True if the pk, message, signature triple verifies, false otherwise.
 */
bool verify(const array<byte, HASH_SIZE> &pk, const vector<byte> &message, const signature_t &signature) {
    return verify_ots(signature, message) && verify_leaf(signature, pk);
}

/**
 * Verify a public key, message, signature triple.
 */
int main(int argc, char *argv[]) {
    string public_key_path = argv[1];
    string message_path = argv[2];
    string signature_path = argv[3];

    array<byte, HASH_SIZE> pk = load_public_key(public_key_path);
    vector<byte> message = read_file(message_path);
    signature_t signature = load_signature(signature_path);

    bool success = verify(pk, message, signature);
    if (!success) {
        cout << "Verification failed." << endl;
        return 1;
    }
    cout << "Verified successfully." << endl;
    return 0;
}
