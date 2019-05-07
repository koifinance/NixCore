#ifndef SIGMA_SIGMAPLUS_PROVER_H
#define SIGMA_SIGMAPLUS_PROVER_H

#include <sigma/r1_proof_generator.h>
#include <sigma/sigmaplus_proof.h>
#include <secp256k1/include/MultiExponent.h>

#include <cstddef>

namespace sigma {

template <class Exponent, class GroupElement>
class SigmaPlusProver{

public:
    SigmaPlusProver(const GroupElement& g,
                    const std::vector<GroupElement>& h_gens, int n, int m);
    void proof(const std::vector<GroupElement>& commits,
               std::size_t l,
               const Exponent& r,
               SigmaPlusProof<Exponent, GroupElement>& proof_out);

private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    int n_;
    int m_;
};

} // namespace sigma

#include "sigmaplus_prover.hpp"

#endif // SIGMA_SIGMAPLUS_PROVER_H
