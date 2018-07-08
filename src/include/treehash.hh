#pragma once
#include <array>
#include <vector>

#include "types.hh"

// See https://www.cdc.informatik.tu-darmstadt.de/reports/reports/AuthPath.pdf

class Treehash
{
private:
    std::vector<merkle_node> *global_stack;
    std::array<byte, HASH_SIZE> secret;
    size_t leaf_index;
    std::vector<merkle_node> *leaves;
    size_t nodes_on_stack;
    bool initialized;
    size_t n_updates;

    // give cereal access to it can serialize private elements
    friend class cereal::access;
    template<class Archive>
    void serialize(Archive & archive) {
        archive( initialized, n_updates, secret, leaf_index, nodes_on_stack, node, h );
    }


public:
    merkle_node leafcalc(size_t leaf_index);
    Treehash(std::array<byte, HASH_SIZE> secret, std::vector<merkle_node>* global_stack, size_t leaf_index = 0, size_t h = -1, std::vector<merkle_node> *leaves = NULL);
    merkle_node node;
    size_t h;
    size_t height();
    std::vector<merkle_node> update(std::vector<merkle_node> *to_save);
    void update();
    Treehash(){}; // empty default constructor for cereal to call
    void initialize(size_t leaf_index);
    void set_stack(std::vector<merkle_node> *global_stack);
};

