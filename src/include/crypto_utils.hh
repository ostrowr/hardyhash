#include <iomanip>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <vector>

typedef unsigned char byte;

#define HASH_SIZE SHA256_DIGEST_LENGTH

std::string print_bytes(const byte *, size_t);
void sha256(byte *in, size_t in_bytes, byte *out);
void sha512(byte *in, size_t in_bytes, byte *out);
void get_randomness(byte *, size_t);
void PRG(const byte *seed, size_t seed_len, byte *buf, size_t buf_len, size_t info);

std::vector<byte> read_file(std::string path);