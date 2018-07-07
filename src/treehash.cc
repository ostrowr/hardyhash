#include "treehash.hh"
#include <iostream>
#include <algorithm>

using std::array;
using std::vector;

/**
 * Constructs the Treehash object.
 *
 * @param[in]  secret        The secret seed used to generate the leaves.
 * @param      global_stack  The global stack shared among several treehash objects
 * @param[in]  leaf_index    The leaf index on which this treehash object starts.
 * @param[in]  h             The height of this treehash object.
 * @param      leaves        The leaves (optional, if missing generated using a PRG using secret.)
 */
Treehash::Treehash(array<byte, HASH_SIZE> secret,
                   vector<merkle_node>* global_stack,
                   size_t leaf_index, size_t h,
                   vector<merkle_node> *leaves) {
    this->secret = secret;
    this->global_stack = global_stack;
    this->leaf_index = leaf_index;
    this->h = h;
    this->nodes_on_stack = 0;
    this->leaves = leaves;  // usually null
    this->initialized = false;
    this->n_updates = 0;
}

/**
 * Reinitialize this treehash object at a specific leaf.
 *
 * @param[in]  leaf_index  The leaf index
 */
void Treehash::initialize(size_t leaf_index) {
    this->leaf_index = leaf_index;
    this->nodes_on_stack = 0;
    this->initialized = true;
    this->n_updates = 0;
    this->leaves = NULL;
}

/**
 * Sets the global stack for this treehash object.
 *
 * @param      global_stack  The global stack
 */
void Treehash::set_stack(vector<merkle_node> *global_stack) {
    this->global_stack = global_stack;
}

/**
 * Calculate the hash at a specific leaf.
 *
 * @param[in]  leaf_index  The leaf index
 *
 * @return     A merkle node at the requested index.
 */
merkle_node Treehash::leafcalc(size_t leaf_index) {
    if (this->leaves != NULL) {
        return (*this->leaves)[leaf_index];
    }
    return ::leafcalc(this->secret.data(), this->secret.size(), leaf_index);
}

/**
 * Make one update step in the treehash algorithm.
 *
 * Calling this repeatedly will eventually construct every node
 * in the tree.
 */
void Treehash::update() {
    this->update(NULL);
}

/**
 * Make one update step in the treehash algorithm.
 *
 * Calling this repeatedly will eventually construct every node
 * in the tree.
 *
 * @param      to_save  Nodes whose hashes should be saved. If null, none are saved.
 *
 * @return     The values of the saved nodes.
 */
vector<merkle_node> Treehash::update(vector<merkle_node> *to_save) {
    merkle_node leaf = leafcalc(this->leaf_index);
    this->leaf_index++;
    vector<merkle_node> saved;

    while (this->nodes_on_stack && (this->global_stack->back().height == leaf.height)) {
        if (to_save != NULL && !to_save->empty()
                            && to_save->back().height == leaf.height
                            && to_save->back().index == leaf.index) {
            saved.push_back(leaf);
            to_save->pop_back();
        }
        merkle_node top = this->global_stack->back();
        this->global_stack->pop_back();
        this->nodes_on_stack--;
        leaf = combine(top, leaf);
    }
    if (to_save != NULL && !to_save->empty()
                        && to_save->back().height == leaf.height
                        && to_save->back().index == leaf.index) {
        saved.push_back(leaf);
        to_save->pop_back();
    }
    global_stack->push_back(leaf);
    this->nodes_on_stack++;

    if (this->nodes_on_stack == 1 && this->global_stack->back().height == this->h) {
        this->initialized = false;
        this->node = global_stack->back();
        this->global_stack->pop_back();
        this->nodes_on_stack--;
    }

    return saved;
}

/**
 * Compute the height of the lowest tail node stored by this treehash instance.
 *
 * @return  this height.
 */
size_t Treehash::height() {
    size_t lowest_height = -1;
    if (!this->initialized) {
        return lowest_height;
    }
    lowest_height = this->h;

    for (size_t i = 0; i < this->nodes_on_stack; i++) {
        size_t ix = this->global_stack->size() - 1 - i;
        merkle_node node = (*(this->global_stack))[ix];
        if (node.height < lowest_height) {
            lowest_height = node.height;
        }
    }

    return lowest_height;
}
