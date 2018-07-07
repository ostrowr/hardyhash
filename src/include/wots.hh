#include <array>
#include <string>
#include <vector>

#include "crypto_utils.hh"

typedef std::vector<std::array<byte, HASH_SIZE> > ots_signature_t;

#define WOTS_CLASS FixedWeightWOTS

class WOTS
{
private:

protected:
    std::array<byte, HASH_SIZE> sk_seed;
    std::array<byte, HASH_SIZE> pk;
    size_t depth;
    size_t width;
    bool used;
    std::vector<byte> derive_sk();
    static std::array<byte, HASH_SIZE> iter_f(std::array<byte, HASH_SIZE>, size_t n_iters);

    virtual void derive_pk() = 0;
    virtual std::vector<size_t> transform_message(std::vector<byte> message) = 0;

public:
    WOTS(std::array<byte, HASH_SIZE> key_material, size_t width, size_t depth);
    WOTS(size_t width, size_t height); // for verification
    std::array<byte, HASH_SIZE> get_pk();
    virtual ots_signature_t sign(std::vector<byte> message) = 0;
    virtual bool verify(std::array<byte, HASH_SIZE> pk, std::vector<byte> message, ots_signature_t signature) = 0;
};

class BasicWOTS: public WOTS
{
private:

protected:
    void derive_pk();
    std::vector<size_t> transform_message(std::vector<byte> message);


public:
    explicit BasicWOTS(std::array<byte, HASH_SIZE> key_material) : WOTS(key_material, 134, 3) {
        this->derive_pk();
    };

    BasicWOTS() : WOTS(134, 3) {};
    ots_signature_t sign(std::vector<byte> message);
    bool verify(std::array<byte, HASH_SIZE> pk, std::vector<byte> message, ots_signature_t signature);
};

class FixedWeightWOTS: public BasicWOTS
{
private:
    const int WeightConstant = 241;

protected:
    std::vector<size_t> transform_message(std::vector<byte> message);

public:
    explicit FixedWeightWOTS(std::array<byte, HASH_SIZE> key_material) : BasicWOTS(key_material) {};
    FixedWeightWOTS() : BasicWOTS() {};
};