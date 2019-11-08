#ifndef SPHINCS_PLUS_SIGN_H
#define SPHINCS_PLUS_SIGN_H

#include "sphincsplus-polyvec.h"

void sphincsplus_expand_mat(sphincsplus_polyvecl *mat,
        const unsigned char rho[SPHINCS_PLUS_SEEDBYTES],
        uint64_t sphincsplus_k, uint64_t sphincsplus_l);

void sphincsplus_challenge(sphincsplus_poly *c,
               const unsigned char mu[SPHINCS_PLUS_CRHBYTES],
               const sphincsplus_polyveck *w1,
               uint64_t sphincsplus_k,
               uint64_t sphincsplus_polw1_size_packed);
#endif
