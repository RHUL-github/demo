#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "sphincsplus-params.h"
#include "sphincsplus-poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  sphincsplus_poly vec[5]; // Max L
} sphincsplus_polyvecl;

void sphincsplus_polyvecl_freeze(sphincsplus_polyvecl *v, uint64_t sphincsplus_l);

void sphincsplus_polyvecl_add(sphincsplus_polyvecl *w, const sphincsplus_polyvecl *u,
        const sphincsplus_polyvecl *v, uint64_t sphincsplus_l);

void sphincsplus_polyvecl_ntt(sphincsplus_polyvecl *v, uint64_t sphincsplus_l);
void sphincsplus_polyvecl_pointwise_acc_invmontgomery(sphincsplus_poly *w,
                                          const sphincsplus_polyvecl *u,
                                          const sphincsplus_polyvecl *v,
                                          uint64_t sphincsplus_l);

int sphincsplus_polyvecl_chknorm(const sphincsplus_polyvecl *v, uint32_t B,
        uint64_t sphincsplus_l);



/* Vectors of polynomials of length K */
typedef struct {
  sphincsplus_poly vec[6]; // Max K
} sphincsplus_polyveck;

void sphincsplus_polyveck_reduce(sphincsplus_polyveck *v, uint64_t sphincsplus_k);
void sphincsplus_polyveck_csubq(sphincsplus_polyveck *v, uint64_t sphincsplus_k);
void sphincsplus_polyveck_freeze(sphincsplus_polyveck *v, uint64_t sphincsplus_k);

void sphincsplus_polyveck_add(sphincsplus_polyveck *w,
        const sphincsplus_polyveck *u, const sphincsplus_polyveck *v,
        uint64_t sphincsplus_k);
void sphincsplus_polyveck_sub(sphincsplus_polyveck *w,
        const sphincsplus_polyveck *u, const sphincsplus_polyveck *v,
        uint64_t sphincsplus_k);
void sphincsplus_polyveck_shiftl(sphincsplus_polyveck *v, uint64_t sphincsplus_k);

void sphincsplus_polyveck_ntt(sphincsplus_polyveck *v, uint64_t sphincsplus_k);
void sphincsplus_polyveck_invntt_montgomery(sphincsplus_polyveck *v,
        uint64_t sphincsplus_k);

int sphincsplus_polyveck_chknorm(const sphincsplus_polyveck *v, uint32_t B,
        uint64_t sphincsplus_k);

void sphincsplus_polyveck_power2round(sphincsplus_polyveck *v1,
        sphincsplus_polyveck *v0, const sphincsplus_polyveck *v,
        uint64_t sphincsplus_k);
void sphincsplus_polyveck_decompose(sphincsplus_polyveck *v1,
        sphincsplus_polyveck *v0, const sphincsplus_polyveck *v,
        uint64_t sphincsplus_k);
unsigned int sphincsplus_polyveck_make_hint(sphincsplus_polyveck *h,
                                const sphincsplus_polyveck *v0,
                                const sphincsplus_polyveck *v1,
                                uint64_t sphincsplus_k);
void sphincsplus_polyveck_use_hint(sphincsplus_polyveck *w,
        const sphincsplus_polyveck *v, const sphincsplus_polyveck *h,
        uint64_t sphincsplus_k);

#endif
