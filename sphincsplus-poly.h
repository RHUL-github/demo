#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "sphincsplus-params.h"

typedef struct {
  uint32_t coeffs[sphincsplus_N];
} sphincsplus_poly __attribute__((aligned(32)));

void sphincsplus_poly_reduce(sphincsplus_poly *a);
void sphincsplus_poly_csubq(sphincsplus_poly *a);
void sphincsplus_poly_freeze(sphincsplus_poly *a);

void sphincsplus_poly_add(sphincsplus_poly *c, const sphincsplus_poly *a, const sphincsplus_poly *b);
void sphincsplus_poly_sub(sphincsplus_poly *c, const sphincsplus_poly *a, const sphincsplus_poly *b);
void sphincsplus_poly_neg(sphincsplus_poly *a);
void sphincsplus_poly_shiftl(sphincsplus_poly *a);

void sphincsplus_poly_ntt(sphincsplus_poly *a);
void sphincsplus_poly_invntt_montgomery(sphincsplus_poly *a);
void sphincsplus_poly_pointwise_invmontgomery(sphincsplus_poly *c, const sphincsplus_poly *a, const sphincsplus_poly *b);

void sphincsplus_poly_power2round(sphincsplus_poly *a1, sphincsplus_poly *a0, const sphincsplus_poly *a);
void sphincsplus_poly_decompose(sphincsplus_poly *a1, sphincsplus_poly *a0, const sphincsplus_poly *a);
unsigned int sphincsplus_poly_make_hint(sphincsplus_poly *h,
        const sphincsplus_poly *a0, const sphincsplus_poly *a1);
void sphincsplus_poly_use_hint(sphincsplus_poly *a, const sphincsplus_poly *b, const sphincsplus_poly *h);

int  sphincsplus_poly_chknorm(const sphincsplus_poly *a, uint32_t B);
void sphincsplus_poly_uniform(sphincsplus_poly *a,
        const unsigned char seed[SPHINCS_PLUS_SEEDBYTES],
        uint16_t nonce);
void sphincsplus_poly_uniform_eta(sphincsplus_poly *a,
                      const unsigned char seed[SPHINCS_PLUS_SEEDBYTES],
                      uint16_t nonce, uint64_t sphincsplus_eta,
                      uint64_t sphincsplus_setabits);
void sphincsplus_poly_uniform_gamma1m1(sphincsplus_poly *a,
                           const unsigned char seed[SPHINCS_PLUS_CRHBYTES],
                           uint16_t nonce);

void sphincsplus_polyeta_pack(unsigned char *r, const sphincsplus_poly *a, uint64_t sphincsplus_eta);
void sphincsplus_polyeta_unpack(sphincsplus_poly *r, const unsigned char *a, uint64_t sphincsplus_eta);

void sphincsplus_polyt1_pack(unsigned char *r, const sphincsplus_poly *a);
void sphincsplus_polyt1_unpack(sphincsplus_poly *r, const unsigned char *a);

void sphincsplus_polyt0_pack(unsigned char *r, const sphincsplus_poly *a);
void sphincsplus_polyt0_unpack(sphincsplus_poly *r, const unsigned char *a);

void sphincsplus_polyz_pack(unsigned char *r, const sphincsplus_poly *a);
void sphincsplus_polyz_unpack(sphincsplus_poly *r, const unsigned char *a);

void sphincsplus_polyw1_pack(unsigned char *r, const sphincsplus_poly *a);
#endif
