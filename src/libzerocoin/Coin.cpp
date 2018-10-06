/**
 * @file       Coin.cpp
 *
 * @brief      PublicCoin and PrivateCoin classes for the Zerocoin library.
 *
 * @author     Ian Miers, Christina Garman and Matthew Green
 * @date       June 2013
 *
 * @copyright  Copyright 2013 Ian Miers, Christina Garman and Matthew Green
 * @license    This project is released under the MIT license.
 **/

#include <stdexcept>
#include <openssl/rand.h>
#include "Zerocoin.h"
#include "../../amount.h"

namespace libzerocoin {
secp256k1_context* init_ctx() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char seed[32];
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        throw ZerocoinException("Unable to generate randomness for context");
    }
    if (secp256k1_context_randomize(ctx, seed) != 1) {
        throw ZerocoinException("Unable to randomize context");
    };
    return ctx;
}
// global context
secp256k1_context* ctx = init_ctx();

//PublicCoin class
PublicCoin::PublicCoin(const Params* p):
    params(p), denomination(ZQ_ONE) {
	if (this->params->initialized == false) {
		throw ZerocoinException("Params are not initialized");
	}
};

PublicCoin::PublicCoin(const Params* p, const Bignum& coin, const CoinDenomination d):
	params(p), value(coin), denomination(d) {
	if (this->params->initialized == false) {
		throw ZerocoinException("Params are not initialized");
	}
};

bool PublicCoin::operator==(const PublicCoin& rhs) const {
	return this->value == rhs.value; // FIXME check param equality
}

bool PublicCoin::operator!=(const PublicCoin& rhs) const {
	return !(*this == rhs);
}

const Bignum& PublicCoin::getValue() const {
	return this->value;
}

CoinDenomination PublicCoin::getDenomination() const {
	return static_cast<CoinDenomination>(this->denomination);
}

bool PublicCoin::validate() const{
    return (this->params->accumulatorParams.minCoinValue < value) && (value < this->params->accumulatorParams.maxCoinValue) && value.isPrime(params->zkp_iterations);
}

//PrivateCoin class
PrivateCoin::PrivateCoin(const Params* p, CoinDenomination denomination, int version): params(p), publicCoin(p) {
    this->version = version;
	// Verify that the parameters are valid
	if(this->params->initialized == false) {
		throw ZerocoinException("Params are not initialized");
	}

#ifdef ZEROCOIN_FAST_MINT
	// Mint a new coin with a random serial number using the fast process.
	// This is more vulnerable to timing attacks so don't mint coins when
	// somebody could be timing you.
	this->mintCoinFast(denomination);
#else
	// Mint a new coin with a random serial number using the standard process.
	this->mintCoin(denomination);
#endif

}

/**
 *
 * @return the coins serial number
 */
const Bignum& PrivateCoin::getSerialNumber() const {
	return this->serialNumber;
}

const Bignum& PrivateCoin::getRandomness() const {
	return this->randomness;
}

const unsigned char* PrivateCoin::getEcdsaSeckey() const {
     return this->ecdsaSeckey;
}

unsigned int PrivateCoin::getVersion() const {
     return this->version;
}

void PrivateCoin::mintCoin(const CoinDenomination denomination) {

	Bignum s;

	// Repeat this process up to MAX_COINMINT_ATTEMPTS times until
	// we obtain a prime number
	for (uint32_t attempt = 0; attempt < MAX_COINMINT_ATTEMPTS; attempt++) {
        if (this->version == 1) {

			// Create a key pair
			secp256k1_pubkey pubkey;
			do {
				if (RAND_bytes(this->ecdsaSeckey, sizeof(this->ecdsaSeckey))
						!= 1) {
					throw ZerocoinException("Unable to generate randomness");
				}
			} while (!secp256k1_ec_pubkey_create(ctx, &pubkey,
					this->ecdsaSeckey));

			// Hash the public key in the group to obtain a serial number
            s = serialNumberFromSerializedPublicKey(ctx, &pubkey, this->pubHash);
		} else {
			// Generate a random serial number in the range 0...{q-1} where
			// "q" is the order of the commitment group.
			s = Bignum::randBignum(
					this->params->coinCommitmentGroup.groupOrder);
		}

		// Generate a Pedersen commitment to the serial number "s"
		Commitment coin(&params->coinCommitmentGroup, s);

		// Now verify that the commitment is a prime number
		// in the appropriate range. If not, we'll throw this coin
		// away and generate a new one.
		if (coin.getCommitmentValue().isPrime(ZEROCOIN_MINT_PRIME_PARAM)
				&& coin.getCommitmentValue()
						>= params->accumulatorParams.minCoinValue
				&& coin.getCommitmentValue()
                        <= params->accumulatorParams.maxCoinValue && coin.getCommitmentValue().bitSize() > params->coinCommitmentGroup.modulus.bitSize()-8) {
			// Found a valid coin. Store it.
			this->serialNumber = s;
			this->randomness = coin.getRandomness();
			this->publicCoin = PublicCoin(params, coin.getCommitmentValue(),
					denomination);

			// Success! We're done.
			return;
		}
	}

	// We only get here if we did not find a coin within
	// MAX_COINMINT_ATTEMPTS. Throw an exception.
	throw ZerocoinException(
			"Unable to mint a new Zerocoin (too many attempts)");
}

void PrivateCoin::mintCoinFast(const CoinDenomination denomination) {
	Bignum s;

    if(this->version == 1) {

		// Create a key pair
		secp256k1_pubkey pubkey;
		do {
			if (RAND_bytes(this->ecdsaSeckey, sizeof(this->ecdsaSeckey)) != 1) {
				throw ZerocoinException("Unable to generate randomness");
			}
		}while (!secp256k1_ec_pubkey_create(ctx, &pubkey, this->ecdsaSeckey));

		// Hash the public key in the group to obtain a serial number
        s = serialNumberFromSerializedPublicKey(ctx, &pubkey, this->pubHash);
	} else {
		// Generate a random serial number in the range 0...{q-1} where
		// "q" is the order of the commitment group.
		s = Bignum::randBignum(this->params->coinCommitmentGroup.groupOrder);
	}

	// Generate a random number "r" in the range 0...{q-1}
	Bignum r = Bignum::randBignum(this->params->coinCommitmentGroup.groupOrder);

	// Manually compute a Pedersen commitment to the serial number "s" under randomness "r"
	// C = g^s * h^r mod p
	Bignum commitmentValue = this->params->coinCommitmentGroup.g.pow_mod(s, this->params->coinCommitmentGroup.modulus).mul_mod(this->params->coinCommitmentGroup.h.pow_mod(r, this->params->coinCommitmentGroup.modulus), this->params->coinCommitmentGroup.modulus);

	// Repeat this process up to MAX_COINMINT_ATTEMPTS times until
	// we obtain a prime number
	for (uint32_t attempt = 0; attempt < MAX_COINMINT_ATTEMPTS; attempt++) {
		// First verify that the commitment is a prime number
		// in the appropriate range. If not, we'll throw this coin
		// away and generate a new one.
		if (commitmentValue.isPrime(ZEROCOIN_MINT_PRIME_PARAM) &&
			commitmentValue >= params->accumulatorParams.minCoinValue &&
            commitmentValue <= params->accumulatorParams.maxCoinValue && commitmentValue.bitSize() > params->coinCommitmentGroup.modulus.bitSize()-8) {
			// Found a valid coin. Store it.
			this->serialNumber = s;
			this->randomness = r;
			this->publicCoin = PublicCoin(params, commitmentValue, denomination);

			// Success! We're done.
			return;
		}

		// Generate a new random "r_delta" in 0...{q-1}
		Bignum r_delta = Bignum::randBignum(this->params->coinCommitmentGroup.groupOrder);

		// The commitment was not prime. Increment "r" and recalculate "C":
		// r = r + r_delta mod q
		// C = C * h mod p
		r = (r + r_delta) % this->params->coinCommitmentGroup.groupOrder;
		commitmentValue = commitmentValue.mul_mod(this->params->coinCommitmentGroup.h.pow_mod(r_delta, this->params->coinCommitmentGroup.modulus), this->params->coinCommitmentGroup.modulus);
	}

	// We only get here if we did not find a coin within
	// MAX_COINMINT_ATTEMPTS. Throw an exception.
	throw ZerocoinException("Unable to mint a new Zerocoin (too many attempts)");
}

const PublicCoin& PrivateCoin::getPublicCoin() const {
	return this->publicCoin;
}


const Bignum PrivateCoin::serialNumberFromSerializedPublicKey(secp256k1_context *context, secp256k1_pubkey *pubkey, uint160& pubHash)  {
    std::vector<unsigned char> pubkey_hash(32, 0);

    static const unsigned char one[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    // We use secp256k1_ecdh instead of secp256k1_serialize_pubkey to avoid a timing channel.
    secp256k1_ecdh(context, pubkey_hash.data(), pubkey, &one[0]);

	std::string zpts(ZEROCOIN_PUBLICKEY_TO_SERIALNUMBER);
	std::vector<unsigned char> pre(zpts.begin(), zpts.end());
    std::copy(pubkey_hash.begin(), pubkey_hash.end(), std::back_inserter(pre));

	uint160 hash;
    CRIPEMD160().Write(pre.data(), pre.size()).Finalize(hash.begin());
    pubHash = hash;
    // Use 160 bits of hash as coin serial. Bignum constuctor expects little-endian sequence of bytes,
    // last zero byte is used to set sign bit to 0
    std::vector<unsigned char> hash_vch(hash.begin(), hash.end());
    hash_vch.push_back(0);
    return Bignum(hash_vch);
}


CoinDenomination IntToZerocoinDenomination(int64_t amount)
{
    CoinDenomination denomination;
    switch (amount) {
    case 1:		denomination = CoinDenomination::ZQ_ONE; break;
    case 5:	denomination = CoinDenomination::ZQ_FIVE; break;
    case 10:	denomination = CoinDenomination::ZQ_TEN; break;
    case 50:	denomination = CoinDenomination::ZQ_FIFTY; break;
    case 100: denomination = CoinDenomination::ZQ_ONE_HUNDRED; break;
    case 500: denomination = CoinDenomination::ZQ_FIVE_HUNDRED; break;
    case 1000: denomination = CoinDenomination::ZQ_ONE_THOUSAND; break;
    case 5000: denomination = CoinDenomination::ZQ_FIVE_THOUSAND; break;
    default:
        //not a valid denomination
        denomination = CoinDenomination::ZQ_ERROR; break;
    }

    return denomination;
}

int64_t ZerocoinDenominationToInt(const CoinDenomination& denomination)
{
    int64_t Value = 0;
    switch (denomination) {
    case CoinDenomination::ZQ_ONE: Value = 1; break;
    case CoinDenomination::ZQ_FIVE: Value = 5; break;
    case CoinDenomination::ZQ_TEN: Value = 10; break;
    case CoinDenomination::ZQ_FIFTY : Value = 50; break;
    case CoinDenomination::ZQ_ONE_HUNDRED: Value = 100; break;
    case CoinDenomination::ZQ_FIVE_HUNDRED: Value = 500; break;
    case CoinDenomination::ZQ_ONE_THOUSAND: Value = 1000; break;
    case CoinDenomination::ZQ_FIVE_THOUSAND: Value = 5000; break;
    default:
        // Error Case
        Value = 0; break;
    }
    return Value;
}

CoinDenomination AmountToZerocoinDenomination(CAmount amount)
{
    // Check to make sure amount is an exact integer number of COINS
    CAmount residual_amount = amount - COIN * (amount / COIN);
    if (residual_amount == 0) {
        return IntToZerocoinDenomination(amount/COIN);
    } else {
        return CoinDenomination::ZQ_ERROR;
    }
}

// return the highest denomination that is less than or equal to the amount given
// use case: converting coins without user worrying about denomination math themselves
CoinDenomination AmountToClosestDenomination(CAmount nAmount, CAmount& nRemaining)
{
    if (nAmount < 1 * COIN)
        return ZQ_ERROR;

    CAmount nConvert = nAmount / COIN;
    CoinDenomination denomination = ZQ_ERROR;
    for (unsigned int i = 0; i < denominationList.size(); i++) {
        denomination = denominationList[i];

        //exact match
        if (nConvert == denomination) {
            nRemaining = 0;
            return denomination;
        }

        //we are beyond the value, use previous denomination
        if (denomination > nConvert && i) {
            CoinDenomination d = denominationList[i - 1];
            nRemaining = nConvert - d;
            return d;
        }
    }
    //last denomination, the highest value possible
    nRemaining = nConvert - denomination;
    return denomination;
}

CAmount ZerocoinDenominationToAmount(const CoinDenomination& denomination)
{
    CAmount nValue = COIN * ZerocoinDenominationToInt(denomination);
    return nValue;
}


CoinDenomination get_denomination(std::string denomAmount) {
    int64_t val = std::stoi(denomAmount);
    return IntToZerocoinDenomination(val);
}


int64_t get_amount(std::string denomAmount) {
    int64_t nAmount = 0;
    CoinDenomination denom = get_denomination(denomAmount);
    if (denom == ZQ_ERROR) {
        nAmount = 0;
    } else {
        nAmount = ZerocoinDenominationToAmount(denom);
    }
    return nAmount;
}

} /* namespace libzerocoin */
