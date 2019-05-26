/**
 * @file       CoinSpend.h
 *
 * @brief      CoinSpend class for the Zerocoin library.
 *
 * @author     Ian Miers, Christina Garman and Matthew Green
 * @date       June 2013
 *
 * @copyright  Copyright 2013 Ian Miers, Christina Garman and Matthew Green
 * @license    This project is released under the MIT license.
 **/

#ifndef COINSPEND_H_
#define COINSPEND_H_

#include "libzerocoin/Params.h"
#include "libzerocoin/Coin.h"
#include "libzerocoin/Commitment.h"
#include "libzerocoin/bignum.h"
#include "libzerocoin/Accumulator.h"
#include "libzerocoin/AccumulatorProofOfKnowledge.h"
#include "libzerocoin/SerialNumberSignatureOfKnowledge.h"
#include "libzerocoin/SpendMetaData.h"
#include "../serialize.h"

namespace libzerocoin {


class CoinSpendReveal{
private:
    uint8_t version;
    CBigNum pubCoinValue;
    CBigNum pubCoinRandomness;

public:
    static const uint8_t CURRENT_VERSION = 2;

    CoinSpendReveal()
    {
        version = 0;
        pubCoinValue = CBigNum(0);
        pubCoinRandomness = CBigNum(0);
    }

    CoinSpendReveal(const CBigNum& pbValue, const Commitment& C1);
    bool Verify(const CBigNum& C2, const Params *zc_params) const;
    CBigNum GetPubcoinValue() const { return pubCoinValue; }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(version);
        READWRITE(pubCoinValue);
        READWRITE(pubCoinRandomness);
    }
};
/** The complete proof needed to spend a zerocoin.
 * Composes together a proof that a coin is accumulated
 * and that it has a given serial number.
 */
class CoinSpend {
private:
    template <typename Stream>
    auto is_eof_helper(Stream &s, bool) -> decltype(s.eof()) {
        return s.eof();
    }

    template <typename Stream>
    bool is_eof_helper(Stream &s, int) {
        return false;
    }

    template<typename Stream>
    bool is_eof(Stream &s) {
        return is_eof_helper(s, true);
    }

public:
	template<typename Stream>
    CoinSpend(const Params* p,  Stream& strm):
		params(p),
        denomination(ZQ_ONE),
		accumulatorPoK(&p->accumulatorParams),
		serialNumberSoK(p),
		commitmentPoK(&p->serialNumberSoKCommitmentGroup, &p->accumulatorParams.accumulatorPoKCommitmentGroup) {
		strm >> *this;
	}
	/**Generates a proof spending a zerocoin.
	 *
	 * To use this, provide an unspent PrivateCoin, the latest Accumulator
	 * (e.g from the most recent Bitcoin block) containing the public part
	 * of the coin, a witness to that, and whatever medeta data is needed.
	 *
	 * Once constructed, this proof can be serialized and sent.
	 * It is validated simply be calling validate.
	 * @warning Validation only checks that the proof is correct
	 * @warning for the specified values in this class. These values must be validated
	 *  Clients ought to check that
	 * 1) params is the right params
	 * 2) the accumulator actually is in some block
	 * 3) that the serial number is unspent
	 * 4) that the transaction
	 *
	 * @param p cryptographic parameters
	 * @param coin The coin to be spend
	 * @param a The current accumulator containing the coin
	 * @param witness The witness showing that the accumulator contains the coin
	 * @param m arbitrary meta data related to the spend that might be needed by Bitcoin
	 * 			(i.e. the transaction hash)
	 * @throw ZerocoinException if the process fails
	 */
	CoinSpend(const Params* p, const PrivateCoin& coin, Accumulator& a, const AccumulatorWitness& witness,
			const SpendMetaData& m, uint256 _accumulatorBlockHash=uint256());

	/** Returns the serial number of the coin spend by this proof.
	 *
	 * @return the coin's serial number
	 */
	const Bignum& getCoinSerialNumber();

	/**Gets the denomination of the coin spent in this proof.
	 *
	 * @return the denomination
	 */
	CoinDenomination getDenomination() const;

	void setVersion(unsigned int nVersion){
        version = nVersion;
	}

    int getVersion() const {
        return version;
    }
	
	uint256 getAccumulatorBlockHash() const {
		return accumulatorBlockHash;
	}

    CBigNum getPubcoinValue() const;

	bool HasValidSerial() const;
	bool Verify(const Accumulator& a, const SpendMetaData &metaData) const;

	ADD_SERIALIZE_METHODS;
	template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
		READWRITE(denomination);
		READWRITE(accCommitmentToCoinValue);
		READWRITE(serialCommitmentToCoinValue);
		READWRITE(coinSerialNumber);
        READWRITE(accumulatorPoK);
        READWRITE(serialNumberSoK);
        READWRITE(commitmentPoK);
        READWRITE(version);
        READWRITE(ecdsaPubkey);
        READWRITE(ecdsaSignature);
        READWRITE(accumulatorBlockHash);
        if(version == ZEROCOIN_VERSION_REDEEM)
            READWRITE(pubcoin_reveal);
	}

private:
	const Params *params;
    const uint256 signatureHash(const SpendMetaData &m) const;
	// Denomination is stored as an INT because storing
	// and enum raises amigiuities in the serialize code //FIXME if possible
	int denomination;
	unsigned int version = 0;
	Bignum accCommitmentToCoinValue;
	Bignum serialCommitmentToCoinValue;
	Bignum coinSerialNumber;
	std::vector<unsigned char> ecdsaSignature;
	std::vector<unsigned char> ecdsaPubkey;
	AccumulatorProofOfKnowledge accumulatorPoK;
	SerialNumberSignatureOfKnowledge serialNumberSoK;
	CommitmentProofOfKnowledge commitmentPoK;
	uint256 accumulatorBlockHash;

    // version 2 spends need to expose the pubcoin of the original mint
    CoinSpendReveal pubcoin_reveal;
};

} /* namespace libzerocoin */
#endif /* COINSPEND_H_ */
