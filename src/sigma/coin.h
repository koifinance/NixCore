#ifndef SIGMA_COIN_H
#define SIGMA_COIN_H

#include <sigma/params.h>
#include <sigma/sigma_primitives.h>

#include <../consensus/validation.h>
#include <../libzerocoin/Zerocoin.h>

#include <cinttypes>

namespace sigma {


enum class CoinDenomination : std::uint8_t {
    SIGMA_0_1 = 0,
    SIGMA_1 = 1,
    SIGMA_10 = 2,
    SIGMA_100 = 3,
    SIGMA_1000 = 4,
    SIGMA_ERROR = 5,
};

static const int SIGMA_VERSION_1 = 1;


// for LogPrintf.
std::ostream& operator<<(std::ostream& stream, CoinDenomination denomination);

// Functions to convert denominations to/from an integer value.
bool DenominationToInteger(CoinDenomination denom, int64_t& denom_out, CValidationState &state);
bool IntegerToDenomination(int64_t value, CoinDenomination& denom_out, CValidationState &state);
bool DenominationToInteger(CoinDenomination denom, int64_t& denom_out);
bool IntegerToDenomination(int64_t value, CoinDenomination& denom_out);
bool StringToDenomination(const std::string& str, CoinDenomination& denom_out);
bool RealNumberToDenomination(const double& value, CoinDenomination& denom_out);

const std::vector<sigma::CoinDenomination> denominationListSigma =
{
    sigma::CoinDenomination::SIGMA_0_1, sigma::CoinDenomination::SIGMA_1, sigma::CoinDenomination::SIGMA_10,
    sigma::CoinDenomination::SIGMA_100, sigma::CoinDenomination::SIGMA_1000
};
sigma::CoinDenomination AmountToClosestDenominationSigma(CAmount nAmount, CAmount& nRemaining);

/// \brief Returns a list of all possible denominations in descending order of value.
void GetAllDenoms(std::vector<sigma::CoinDenomination>& denominations_out);

class PublicCoin {
public:
    PublicCoin();

    PublicCoin(const GroupElement& coin, const CoinDenomination d);

    const GroupElement& getValue() const;
    CoinDenomination getDenomination() const;

    bool operator==(const PublicCoin& other) const;
    bool operator!=(const PublicCoin& other) const;
    bool validate() const;
    size_t GetSerializeSize() const;

    template<typename Stream>
    inline void Serialize(Stream& s) const {
        int size = value.memoryRequired();
        unsigned char buffer[34 + sizeof(int32_t)];
        value.serialize(buffer);
        std::memcpy(buffer + size, &denomination, sizeof(denomination));
        char* b = (char*)buffer;
        s.write(b, size + sizeof(int32_t));
    }

    template<typename Stream>
    inline void Unserialize(Stream& s) {
        int size = value.memoryRequired();
        unsigned char buffer[34 + sizeof(int32_t)];
        char* b = (char*)buffer;
        s.read(b, size + sizeof(int32_t));
        value.deserialize(buffer);
        std::memcpy(&denomination, buffer + size, sizeof(denomination));
    }

private:
    GroupElement value;
    CoinDenomination denomination;
};

class PrivateCoin {
public:
    template<typename Stream>
    PrivateCoin(const Params* p, Stream& strm): params(p), publicCoin() {
        strm >> *this;
    }

    PrivateCoin(const Params* p,
        CoinDenomination denomination,
        int version = SIGMA_VERSION_1);

    const Params * getParams() const;
    const PublicCoin& getPublicCoin() const;
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    unsigned int getVersion() const;
    void setPublicCoin(const PublicCoin& p);
    void setRandomness(const Scalar& n);
    void setSerialNumber(const Scalar& n);
    void setVersion(unsigned int nVersion);
    const unsigned char* getEcdsaSeckey() const;

    void setEcdsaSeckey(const std::vector<unsigned char> &seckey);
    void setEcdsaSeckey(uint256 &seckey);

    static Scalar serialNumberFromSerializedPublicKey(
        const secp256k1_context *context,
        secp256k1_pubkey *pubkey);

private:
    const Params* params;
    PublicCoin publicCoin;
    Scalar randomness;
    Scalar serialNumber;
    unsigned int version = 0;
    unsigned char ecdsaSeckey[32];

    void mintCoin(const CoinDenomination denomination);

};


// Serialization support for CoinDenomination

inline unsigned int GetSerializeSize(CoinDenomination d)
{
    return sizeof(d);
}

template<typename Stream>
void Serialize(Stream& os, CoinDenomination d)
{
    Serialize(os, static_cast<std::uint8_t>(d));
}

template<typename Stream>
void Unserialize(Stream& is, CoinDenomination& d)
{
    std::uint8_t v;
    Unserialize(is, v);
    d = static_cast<CoinDenomination>(v);
}

// Custom hash for Scalar values.
struct CScalarHash {
    std::size_t operator()(const secp_primitives::Scalar& bn) const noexcept;
};

// Custom hash for the public coin.
struct CPublicCoinHash {
    std::size_t operator()(const PublicCoin& coin) const noexcept;
};

}// namespace sigma

namespace std {

string to_string(::sigma::CoinDenomination denom);

template<> struct hash<sigma::CoinDenomination> {
    std::size_t operator()(const sigma::CoinDenomination &f) const {
        return std::hash<int>{}(static_cast<int>(f));
    }
};

}// namespace std

#endif // SIGMA_COIN_H
