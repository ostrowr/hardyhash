#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main()
#include "catch.hpp"

#include <sys/stat.h>
#include <iostream>
#include <cassert>

#include "crypto_utils.hh"
#include "treehash.hh"
#include "sign.hh"
#include "verify.hh"
#include "initialize.hh"

using namespace std;

TEST_CASE("tests working") {
    REQUIRE(0 == 0);
}

TEST_CASE("initialize creates valid public key", "[initialize]") {
    const byte* randomness = (byte *) "randomness";
    keys_t *keys = initialize(4, 4, randomness, 10);
    string pk = print_bytes(keys->public_key.data(), HASH_SIZE);
    REQUIRE(pk == "b5730b639bd2b93074e417fd4be16bfb19751ac13e18ac567ba3b58684699d3e");
    REQUIRE(keys->signer_states.size() == 1 << 4);
    delete keys;
}

TEST_CASE("sha256 gives correct output", "[crypto_utils]") {
    byte *sha_input = (byte *) "sha256";
    byte sha_out[HASH_SIZE];
    sha256(sha_input, 6, sha_out);
    string desired = "5d5b09f6dcb2d53a5fffc60c4ac0d55fabdf556069d6631545f42aa6e3500f2e";
    string received = print_bytes(sha_out, HASH_SIZE);
    REQUIRE(desired == received);
}

TEST_CASE("treehash with explicit leaves computes correct root", "[treehash]") {
    array<byte, HASH_SIZE> seed;
    seed.fill(42);
    merkle_node leaf0, leaf1, leaf2, leaf3;
    leaf0.index = 0;
    leaf0.height = 0;
    leaf1.index = 1;
    leaf1.height = 0;
    leaf2.index = 2;
    leaf2.height = 0;
    leaf3.index = 3;
    leaf3.height = 0;
    PRG(seed.data(), HASH_SIZE, leaf0.hash.data(), HASH_SIZE, 0);
    PRG(seed.data(), HASH_SIZE, leaf1.hash.data(), HASH_SIZE, 1);
    PRG(seed.data(), HASH_SIZE, leaf2.hash.data(), HASH_SIZE, 2);
    PRG(seed.data(), HASH_SIZE, leaf3.hash.data(), HASH_SIZE, 3);
    /*
    Leaves:
    66020db0cff30cd94d511cb1300c8abe29bce36b4acaf0531fa2587dd9c53b59
    70c09c9b1670059d558c07ed53de184bcb296bb32779caecb08323fbebcc8250
    8945c414df73d2785b79d4fc017b61ba724c1a736a18649282042abdbd1fba0b
    f23ae132e30d5cd71fd5df8020dc8f5c07000c5ef829cd6dbc759702ded8c8b4

    Height 1:
    12dd39099be4c0e4cb81be6aa2180d7504eb165b32777b23146d21a940d57752
    e2d814385986be9326917b63f9f308aab9d19764f43bfb0e95cac1ba96601b2d

    Root (height 2):
    12ba80836d8bb85de4f7243ed14f3b6889ac586e8d91d42593a0df63201fc1e7
    */

    vector<merkle_node> global_stack;
    vector<merkle_node> leaves {leaf0, leaf1, leaf2, leaf3};
    Treehash t(seed, &global_stack, 0, 2, &leaves);
    for (size_t i = 0; i < 1<<2; i++) {
        t.update();
    }
    string root = print_bytes(t.node.hash.data(), HASH_SIZE);
    REQUIRE(root == "12ba80836d8bb85de4f7243ed14f3b6889ac586e8d91d42593a0df63201fc1e7");
}

TEST_CASE("wots verifies correct OTS but does not verify incorrect", "[wots]") {
    array<byte, HASH_SIZE> randomness;
    get_randomness(randomness.data(), HASH_SIZE);
    BasicWOTS w(randomness);
    vector<byte> test_msg {1, 2, 3, 4};
    vector<byte> fail_msg {1, 2, 3, 4, 5};

    auto sig = w.sign(test_msg);
    BasicWOTS w2;
    REQUIRE(w2.verify(w.get_pk(), test_msg, sig));
    REQUIRE(!w2.verify(w.get_pk(), fail_msg, sig));
}

TEST_CASE("initialize, sign, and verify", "[initialize, sign, verify]") {
    const byte* randomness = (byte *) "otherrandomness";
    keys_t *keys = initialize(4, 4, randomness, 15);
    REQUIRE(keys->signer_states.size() == 1 << 4);
    mkdir("/tmp/hardyhash_tests", S_IRUSR | S_IWUSR | S_IXUSR);
    write_signer_states(keys, "/tmp/hardyhash_tests");
    vector<byte> msg {4, 2, 4, 2, 9};
    vector<byte> msg2 {1, 2, 3, 4, 5};
    array<byte, HASH_SIZE> pk = load_public_key("/tmp/hardyhash_tests/public_key");
    for (size_t i = 0; i < (1 << 4); i++) {
        msg[4] = i;
        signature_t signature = sign("/tmp/hardyhash_tests/signer_0", msg);
        REQUIRE(verify(pk, msg, signature));
        REQUIRE(!verify(pk, msg2, signature));
    }
    delete keys;
}
