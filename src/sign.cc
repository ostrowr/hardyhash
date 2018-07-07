#include <strings.h>
#include <stdio.h>
#include <fstream>

#include "treehash.hh"

using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::vector;

/**
 * The height of the first parent of which is a left node.
 *
 * Depends on ffs being defined on the architecture used.
 *
 * @param      leaf_index  The leaf index
 *
 * @return     The height of this index.
 */
#define TAU(leaf_index) (ffs(leaf_index + 1) - 1)

/**
 * Print help message for ./sign.
 */
void print_usage() {
    cout << endl << "Usage:" << endl
         << "\t ./sign <path to state file> <path to message file> <path to outfile>" << endl << endl;
    exit(1);
}

/**
 * Loads signer information from a state file.
 *
 * @param[in]  path  The path to the state file.
 *
 * @return     Relevant signer information to sign the next message.
 */
signer_info_t *load_signer_info(string path) {
    std::ifstream is(path);
    cereal::BinaryInputArchive iarchive(is);
    signer_info_t *signer_info = new signer_info_t;
    iarchive(*signer_info);
    for (auto &t : signer_info->treehash_instances) {
        t.set_stack(&(signer_info->treehash_stack));
    }
    return signer_info;
}

/**
 * Serialize signer information to a state file.
 *
 * @param[in]  path         The path to the state file
 * @param[in]  signer_info  The signer information
 */
void write_signer_info(string path, signer_info_t signer_info) {
    std::ofstream os(path);
    cereal::BinaryOutputArchive oarchive(os);
    oarchive(signer_info);
}

/**
 * @brief      Write a signature.
 *
 * @param[in]  signature  The signature
 * @param[in]  path       The output path.
 */
void write_signature(const signature_t &signature, string path) {
    std::ofstream os(path);
    cereal::BinaryOutputArchive oarchive(os);
    oarchive(signature);  // TODO check success
}

/**
 * @brief      Update a signer's authentication path after signing a message.
 *
 * This algorithm is described in detail in Merkle Tree Traversal Revisited
 * (Buchmann et. al.)
 *
 * @param      signer_info  The signer information
 */
void update_auth_path(signer_info_t *signer_info) {
    size_t leaf_index = signer_info->auth_path.front().index;
    if (leaf_index % 2)
        leaf_index--;
    else
        leaf_index++;

    size_t H = signer_info->keep.size();

    // step 1
    size_t tau = TAU(leaf_index);

    // step 2
    bool parent_even = (leaf_index / (1 << (tau + 1))) % 2 == 0;


    if (tau < H + 1 && parent_even) {
        signer_info->keep[tau] = signer_info->auth_path[tau];
    }

    // step 3
    if (tau == 0) {
        signer_info->auth_path[0] = leafcalc(signer_info->secret_key.data(),
                                             signer_info->secret_key.size(),
                                             leaf_index);
    } else {  // step 4
        // a
        signer_info->auth_path[tau] = combine(signer_info->auth_path[tau - 1], signer_info->keep[tau - 1]);

        // b
        for (size_t h = 0; h < tau; h++) {
            if (h == H - 2) {
                signer_info->auth_path[h] = signer_info->retain;
            } else {
                signer_info->auth_path[h] = signer_info->treehash_instances[h].node;
            }

            // c
            size_t new_start_index = 1 + leaf_index + 3 * (1 << h);
            if (new_start_index < (size_t) (1 << H)) {
                signer_info->treehash_instances[h].initialize(new_start_index);
            }
        }
    }

    // step 5
    for (size_t i = 0; i <= H / 2 - 1; i++) {
        size_t best_height = -1;
        size_t best_ix = -1;
        for (size_t i = 0; i < signer_info->treehash_instances.size(); i++) {
            size_t ht = signer_info->treehash_instances[i].height();
            if (ht < best_height) {
                best_height = ht;
                best_ix = i;
            }
        }
        if (best_ix != (size_t) -1) {
            signer_info->treehash_instances[best_ix].update();
        }
    }
}

/**
 * Sign a message
 *
 * @param[in]  state_path  The signer's key state
 * @param[in]  message     The message to sign
 *
 * @return     The signature
 */
signature_t sign(string state_path, const vector<byte> &message) {
    // signature is already totally computed in the previous step
    // but we have to do some housekeeping
    // to make sure the state is updated before we return it.
    signer_info_t *signer_info = load_signer_info(state_path);

    signature_t signature;
    signature.auth_path = signer_info->auth_path;

    size_t leaf_index = signature.auth_path.front().index;
    if (leaf_index % 2)
        leaf_index--;
    else
        leaf_index++;

    // now update state.
    size_t signatures_allowed = 1 << signer_info->keep.size();

    if (leaf_index >= signatures_allowed || signer_info->exhausted) {
        cerr << "ERROR: Attempted to sign more signatures than allowed." << endl;
        cerr << "This key should be deleted, and no more signatures should be derived from this file." << endl;
        exit(1);
    }

    if (leaf_index < signatures_allowed - 1) {
        // update state file before returning the signature
        cout << "Signing message " << leaf_index + 1 << " of " << signatures_allowed << " allowed." << endl;
        update_auth_path(signer_info);
        write_signer_info(state_path, *signer_info);
    }


    if (leaf_index == signatures_allowed - 1) {
        cout << "Signing message " << leaf_index + 1 << " of " << signatures_allowed << " allowed." << endl;
        cout << "This is the last signature that this state file can support." << endl;
        // just in case it isn't deleted properly, write a marker info file:
        signer_info->exhausted = true;
        write_signer_info(state_path, *signer_info);

        if (remove(state_path.c_str()) != 0) {
            cout << "State file could not be removed. Please delete "
                 << state_path
                 << " as it is no longer useful."
                 << endl;
        } else {
            cout << "State file removed." << endl;
        }
    }

    WOTS_CLASS w = wotscalc(signer_info->secret_key.data(), signer_info->secret_key.size(), leaf_index);
    signature.ots = w.sign(message);
    signature.leaf.height = 0;
    signature.leaf.index = leaf_index;
    signature.leaf.hash = w.get_pk();

    delete signer_info;
    return signature;
}



/**
 * Sign a message!
 */
int main(int argc, char *argv[]) {
    if (argc != 4) {
        print_usage();
    }

    // TODO error checking on the inputs
    string state_path = argv[1];
    string message_path = argv[2];
    string signature_path = argv[3];
    vector<byte> message = read_file(message_path);
    signature_t signature = sign(state_path, message);
    write_signature(signature, signature_path);
}
