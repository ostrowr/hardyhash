#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>

#include <sstream>


#include "crypto_utils.hh"

using std::cerr;
using std::cout;
using std::endl;
using std::runtime_error;
using std::string;
using std::vector;

/**
 * Convert raw bytes to a hexadecimal representation.
 *
 * @param[in]  bytes    bytes to print
 * @param[in]  in_size  number of bytes
 *
 * @return     hex representation of bytes.s
 */
string print_bytes(const byte *bytes, size_t in_size) {
    std::stringstream ss;
    for (unsigned int i = 0; i < in_size; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

/**
 * Compute the sha256 hash of some string.
 *
 * Uses OpenSSL's sha256 implementation.
 *
 * @param      in       The message to hash.
 * @param[in]  in_size  Size of in.
 * @param      out      The out
 */
void sha256(byte *in, size_t in_size, byte *out) {
    SHA256(in, in_size, out);
}

/**
 * Compute the sha512 hash of some string.
 *
 * Uses OpenSSL's sha512 implementation.
 *
 * @param      in       The message to hash.
 * @param[in]  in_size  Size of in.
 * @param      out      The hash output.
 */
void sha512(byte *in, size_t in_size, byte *out) {
    SHA512(in, in_size, out);
}

/**
 * Attempt to get hardware randomness.
 *
 * Uses the hardware variant of OpenSSL's RAND_bytes.
 *
 * @param      buf      The buffer to fill
 * @param[in]  n_bytes  The number of bytes of randomness to generate.
 *
 * WARNING: THIS IS JUST A UTILITY FUNCTION AND MAY NOT GENERATE
 * SECURE BYTES ON ALL SYSTEMS. INITIALIZE SHOULD BE SEEDED WITH
 * TRULY RANDOM BYTES.
 */
void get_randomness(byte *buf, size_t n_bytes) {
    /* START OPENSSL CODE */
    unsigned long err = 0;
    int rc = 0;

    // OPENSSL_cpuid_setup(); // only works on IA-32
    ENGINE_load_rdrand();

    ENGINE* eng = ENGINE_by_id("rdrand");
    err = ERR_get_error();

    if (NULL == eng) {
        fprintf(stderr, "ENGINE_load_rdrand failed, err = 0x%lx\n", err);
        abort(); /* failed */
    }

    rc = ENGINE_init(eng);
    err = ERR_get_error();

    if (0 == rc) {
        fprintf(stderr, "ENGINE_init failed, err = 0x%lx\n", err);
        abort(); /* failed */
    }

    rc = ENGINE_set_default(eng, ENGINE_METHOD_RAND);
    err = ERR_get_error();

    if (0 == rc) {
        fprintf(stderr, "ENGINE_set_default failed, err = 0x%lx\n", err);
        abort(); /* failed */
    }
    /* OK to proceed */

    /* END OPENSSL CODE */
    rc = RAND_bytes(buf, n_bytes);
    if (rc != 1) {
        cerr << "Could not generate keys; RAND_bytes failed." << endl;
        exit(1);
    }

    /* START OPENSSL CODE */
    ENGINE_finish(eng);
    ENGINE_free(eng);
    ENGINE_cleanup();
    /* END OPENSSL CODE */
}

/**
 * General-use PRG using OpenSSL hkdf.
 *
 * example:
 *  byte *seed = sha256("sha");
 *  byte buf[32];
 *  PRG(seed, 32, buf, 32, i);
 *  cout << print_bytes(buf, 32) << endl;
 *
 * @param[in]  seed      The random seed. Must be a sufficient source of entropy.
 * @param[in]  seed_len  The seed length
 * @param      buf       The output buffer
 * @param[in]  buf_len   The buffer length
 * @param[in]  info      The extra information
 */
void PRG(const byte *seed, size_t seed_len, byte *buf, size_t buf_len, size_t info) {
    const char *info_str = std::to_string(info).c_str();

    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    // see https://github.com/openssl/openssl/blob/c16ab9dc6303e42519559f6053bf7e4931203a79/doc/man3/EVP_PKEY_CTX_set_hkdf_md.pod
    if (EVP_PKEY_derive_init(pctx) <= 0)
        throw runtime_error("Error: initializing HKDF failed..");
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        throw runtime_error("Error: HKDF hash function failed.");
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "salty salt for hbs", 4) <= 0)
        cerr << "error!" << endl;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, seed, seed_len) <= 0)
        throw runtime_error("Error: setting HKDF key failed.");
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info_str, strlen(info_str)) <= 0)
        throw runtime_error("Error: setting HKDF info failed.");
    if (EVP_PKEY_derive(pctx, buf, &buf_len) <= 0)
        throw runtime_error("Error: HKDF failed.");
    EVP_PKEY_CTX_free(pctx);
}

/**
 * Reads a file into a vector of bytes.
 *
 * @param[in]  path  The path to the file.
 *
 * @return     A vector containing the raw bytes in the file.
 */
vector<byte> read_file(string path) {
    // TODO move hashing here such that
    // we never have to read the whole file
    // into memory.
    std::ifstream is(path, std::ifstream::binary);
    is.seekg(0, is.end);
    size_t n_bytes = is.tellg();
    is.seekg(0, is.beg);
    vector<byte> data(n_bytes);
    is.read(reinterpret_cast<char *>(data.data()), n_bytes);
    if (!is) {
        throw "File could not be read.";
    }
    return data;
}
