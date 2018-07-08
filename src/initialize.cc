#include "initialize.hh"


#include <algorithm>
#include <array>
#include <cassert>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <thread>

#include <cereal/archives/binary.hpp>
#include <cereal/types/array.hpp>
#include <cereal/types/stack.hpp>
#include <cereal/types/vector.hpp>

// #include "treehash.hh"

using std::array;
using std::cout;
using std::endl;
using std::make_pair;
using std::map;
using std::pair;
using std::string;
using std::vector;

/**
 * Generate a secret key for each signer.
 *
 * @param[in]  n_keys           The n keys
 * @param      randomness       The randomness
 * @param[in]  randomness_size  The randomness size
 *
 * @return     A vector containing the secret keys.
 */
vector<array<byte, HASH_SIZE> > generate_secret_keys(size_t n_keys, const byte *randomness, size_t randomness_size) {
    vector<array<byte, HASH_SIZE> > secret_keys(n_keys);
    cout << "Generating " << n_keys << " secret keys." << endl;
    for (unsigned int i = 0; i < n_keys; i++) {
        cout << i << "/" << n_keys << "\r";
        cout.flush();
        PRG(randomness, randomness_size, secret_keys[i].data(), HASH_SIZE, i);
    }
    cout << "Keys generated successfully." << endl;
    return secret_keys;
}

/**
 * Compute a single signer's subtree.
 *
 * @param[in]  secret_key  The signer's secret key
 * @param[in]  height      The height of the subtree.
 *
 * @return     The incomplete initialization state
 *             (still missing the top of the auth path.)
 */
signer_info_t initialize_subtree(array<byte, HASH_SIZE> secret_key, size_t height) {
    signer_info_t signer_state;
    signer_state.secret_key = secret_key;
    signer_state.auth_path.resize(height);
    signer_state.keep.resize(height - 0);
    signer_state.exhausted = false;
    Treehash t(secret_key, &signer_state.treehash_stack, 0, height);
    for (size_t h = 0; h <= height - 2; h++) {
        Treehash tinner(secret_key, &signer_state.treehash_stack, 0, h);
        signer_state.treehash_instances.push_back(tinner);
    }

    vector<merkle_node> to_save;
    for (size_t i = 0; i < height; i ++) {
        // save the auth path
        merkle_node placeholder;
        placeholder.height = i;
        placeholder.index = 1;
        to_save.push_back(placeholder);
    }
    for (size_t i = 0; i < height - 1; i ++) {
        // save for treehash.node and RETAIN node
        merkle_node placeholder;
        placeholder.height = i;
        placeholder.index = 3;
        to_save.push_back(placeholder);
    }

    // save the root
    merkle_node root_placeholder;
    root_placeholder.height = height;
    root_placeholder.index = 0;
    to_save.push_back(root_placeholder);

    sort(to_save.begin(), to_save.end());
    reverse(to_save.begin(), to_save.end());

    vector<merkle_node> saved;
    saved.reserve(to_save.size());
    for (int i = 0; i < 1 << height; i++) {
        vector<merkle_node> newly_saved = t.update(&to_save);
        saved.insert(saved.end(), newly_saved.begin(), newly_saved.end());
    }

    // assign relevant saved values to their positions in the signer_state.
    for (merkle_node mn : saved) {
        if (mn.index == 1)
            signer_state.auth_path[mn.height] = mn;
        else if (mn.index == 3 && mn.height < height - 2)
            signer_state.treehash_instances[mn.height].node = mn;
        else if (mn.index == 3 && mn.height == height - 2)
            signer_state.retain = mn;
        else if (mn.index == 0 && mn.height == height)
            signer_state.root = mn;
    }
    return signer_state;
}

/**
 * Initialize each of the signers' subtrees.
 *
 * @param[in]  secret_keys             The secret keys for each signer
 * @param[in]  lg_messages_per_signer  The height of each subtree.
 *
 * @return     Initialization states for each signer without the top of the auth path.
 */
vector<signer_info_t> initialize_subtrees(vector<array<byte, HASH_SIZE>> secret_keys, size_t lg_messages_per_signer) {
    vector<signer_info_t> signer_states(secret_keys.size());
    cout << "Initializing " << secret_keys.size() << " subtrees, each of height " << lg_messages_per_signer << endl;
    vector<std::future<signer_info_t> > future_signer_info(secret_keys.size());
    for (size_t i = 0; i < secret_keys.size(); i++) {
        // Hooray for new C++ threading!
        future_signer_info[i] = async(initialize_subtree, secret_keys[i], lg_messages_per_signer);
    }
    // TODO use a ThreadPool with maxhardwareconcurrency threads
    for (size_t i = 0; i < secret_keys.size(); i++) {
        signer_states[i] = future_signer_info[i].get();
    }

    cout << "Initialization successful." << endl;
    return signer_states;
}

/**
 * Calculate the shared top of the merkle tree.
 *
 * @param      keys  The information that's been calculated for the subtrees.
 *
 * @return     A vector containing every node in the top of the tree.
 */
vector<merkle_node> initialize_treetop(keys_t *keys) {
    cout << "Calculating public key..." << endl;
    vector<merkle_node> subtree_roots;
    subtree_roots.reserve(keys->signer_states.size());
    for (size_t i = 0; i < keys->signer_states.size(); i++) {
        merkle_node root = keys->signer_states[i].root;
        root.height = 0;
        root.index = i;
        subtree_roots.push_back(root);
    }
    vector<merkle_node> global_stack;
    array<byte, HASH_SIZE> empty_secret;
    // TODO replace 1000 with log keys->n_signers (or -1)
    Treehash t(empty_secret, &global_stack, 0, 1000, &subtree_roots);
    vector<merkle_node> to_save;
    to_save.reserve(keys->n_signers * 2 - 1);
    for (size_t h = 0; (size_t) (1 << h) <= keys->n_signers; h++) {
        for (size_t ix = 0; ix < keys->n_signers / (1 << h); ix++) {
            merkle_node placeholder;
            placeholder.height = h;
            placeholder.index = ix;
            to_save.push_back(placeholder);
        }
    }
    sort(to_save.begin(), to_save.end());
    reverse(to_save.begin(), to_save.end());

    vector<merkle_node> saved;
    saved.reserve(to_save.size());
    for (size_t i = 0; i < keys->n_signers; i++) {
        vector<merkle_node> newly_saved = t.update(&to_save);
        saved.insert(saved.end(), newly_saved.begin(), newly_saved.end());
    }
    cout << "Public key calculated." << endl;
    return saved;
}

/**
 * @brief      Initialize all of the key information.
 *
 * @param[in]  lg_n_signers            lg(number of signers)
 * @param[in]  lg_messages_per_signer  lg(number of messages for each signer.)
 * @param[in]  randomness              Random bytes to act as a seed.
 * @param[in]  randomness_size         Size of randomness.
 *
 * @return     Initial signer states for all signers, and a global public key.
 */
keys_t *initialize(size_t lg_n_signers, size_t lg_messages_per_signer, const byte *randomness, size_t randomness_size) {
    assert(lg_n_signers <= 16);
    assert(lg_messages_per_signer <= 16);
    assert(lg_n_signers % 2 == 0);
    assert(lg_messages_per_signer % 2 == 0);
    keys_t *k = new keys_t;
    k->n_signers = 1 << lg_n_signers;
    vector<array<byte, HASH_SIZE>> secret_keys = generate_secret_keys(k->n_signers, randomness, randomness_size);
    k->signer_states = initialize_subtrees(secret_keys, lg_messages_per_signer);
    vector<merkle_node> treetop = initialize_treetop(k);
    map<pair<unsigned char, unsigned int>, merkle_node > treetop_map;
    for (merkle_node node : treetop)
        treetop_map[make_pair(node.height, node.index)] = node;
    for (size_t i = 0; i < k->signer_states.size(); i++) {
        size_t index = i;
        for (unsigned char height = 0; height < lg_n_signers; height++) {
            size_t neighbor = index + 1;
            if (index % 2 == 1) {
                neighbor = index - 1;
            }
            merkle_node neighbor_data = treetop_map[make_pair(height, neighbor)];
            neighbor_data.height += lg_n_signers;
            k->signer_states[i].auth_path.push_back(neighbor_data);
            index = index / 2;
        }
    }

    k->public_key = treetop_map[make_pair(lg_n_signers, 0)].hash;
    return k;
}

/**
 * Print help message for initialize.
 */
void print_initialize_usage() {
    cout << endl << "Usage:" << endl
         << "\t ./initialize lg_n_signers lg_messages_per_signer randomness output_dir" << endl << endl
         << "\t lg_n_signers must be an even integer between 2 and 16, inclusive." << endl
         << "\t lg_messages_per_signer must be an even integer between 2 and 16, inclusive" << endl
         << "\t randomness should be a source of entropy, at most 1024 characters long" << endl
         << "\t output_dir must be a path to an empty directory." << endl << endl;
    exit(1);
}

/**
 * Writes signer states to a an existing directory.
 *
 * @param      k           the key info for all signers, derived from initialize.
 * @param[in]  output_dir  The output directory.
 */
void write_signer_states(keys_t *k, string output_dir) {
    for (size_t i = 0; i < k->signer_states.size(); i++) {
        std::ofstream os(output_dir + "/signer_" + std::to_string(i));
        cereal::BinaryOutputArchive oarchive(os);
        oarchive(k->signer_states[i]);
    }
    std::ofstream os(output_dir + "/public_key");
    cereal::BinaryOutputArchive oarchive(os);
    oarchive(k->public_key);
}

// int main2(int argc, char *argv[]) {
//     if (argc != 5) {
//         print_usage();
//     }
//     // TODO error checking on the inputs
//     size_t lg_n_signers = std::stoi(argv[1]);
//     size_t lg_messages_per_signer = std::stoi(argv[2]);
//     string randomness = argv[3];
//     string output_dir = argv[4];
//     keys_t *k = initialize(lg_n_signers, lg_messages_per_signer,
//                            reinterpret_cast<const byte *>(randomness.c_str()),
//                            randomness.length());
//     write_signer_states(k, output_dir);
//     delete k;
//     return 0;
// }
