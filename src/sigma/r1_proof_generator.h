#ifndef SIGMA_R1_PROOF_GENERATOR_H
#define SIGMA_R1_PROOF_GENERATOR_H

#include <sigma/r1_proof.h>
#include <sigma/sigma_primitives.h>

namespace sigma {

template <class Exponent, class GroupElement>
class R1ProofGenerator{

public:
    R1ProofGenerator(const GroupElement& g,
                     const std::vector<GroupElement>& h_gens,
                     const std::vector<Exponent>& b,
                     const Exponent& r,
                     int n, int m);

    GroupElement get_B() const { return  B_Commit; }

    void proof(R1Proof<Exponent, GroupElement>& proof_out) const;

    void proof(std::vector<Exponent>& a, R1Proof<Exponent, GroupElement>& proof_out) const;

    mutable Exponent x_;

private:
    const GroupElement& g_;
    const std::vector<GroupElement>& h_;
    std::vector<Exponent> b_;
    Exponent r;
    GroupElement B_Commit;
    int n_; int m_;
};

} // namespace sigma

#include "r1_proof_generator.hpp"

#endif // SIGMA_R1_PROOF_GENERATOR_H
