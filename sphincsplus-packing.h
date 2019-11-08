#ifndef PACKING_H
#define PACKING_H

#include "sphincsplus-params.h"
#include "sphincsplus-polyvec.h"

void sphincsplus_pack_pk(unsigned char *pk,
             const unsigned char rho[SPHINCS_PLUS_SEEDBYTES], const sphincsplus_polyveck *t1,
             uint64_t sphincsplus_k, uint64_t sphincsplus_polt1_size_packed);
void sphincsplus_pack_sk(unsigned char *sk,
             const unsigned char rho[SPHINCS_PLUS_SEEDBYTES],
             const unsigned char key[SPHINCS_PLUS_SEEDBYTES],
             const unsigned char tr[SPHINCS_PLUS_CRHBYTES],
             const sphincsplus_polyvecl *s1,
             const sphincsplus_polyveck *s2,
             const sphincsplus_polyveck *t0,
             uint64_t sphincsplus_k,
             uint64_t sphincsplus_l,
             uint64_t sphincsplus_poleta_size_packed,
             uint64_t sphincsplus_polt0_size_packed,
             uint64_t sphincsplus_eta);
void sphincsplus_pack_sig(unsigned char *sig,
              const sphincsplus_polyvecl *z, const sphincsplus_polyveck *h, const sphincsplus_poly *c,
              uint64_t sphincsplus_k, uint64_t sphincsplus_l,
              uint64_t sphincsplus_polz_size_packed, uint64_t sphincsplus_omega);

void sphincsplus_unpack_pk(unsigned char rho[SPHINCS_PLUS_SEEDBYTES], sphincsplus_polyveck *t1,
               const unsigned char *pk,
               uint64_t sphincsplus_k, uint64_t sphincsplus_polt1_size_packed);
void sphincsplus_unpack_sk(unsigned char rho[SPHINCS_PLUS_SEEDBYTES],
               unsigned char key[SPHINCS_PLUS_SEEDBYTES],
               unsigned char tr[SPHINCS_PLUS_CRHBYTES],
               sphincsplus_polyvecl *s1,
               sphincsplus_polyveck *s2,
               sphincsplus_polyveck *t0,
               const unsigned char *sk,
               uint64_t sphincsplus_k,
               uint64_t sphincsplus_l,
               uint64_t sphincsplus_poleta_size_packed,
               uint64_t sphincsplus_polt0_size_packed,
               uint64_t sphincsplus_eta);
int sphincsplus_unpack_sig(sphincsplus_polyvecl *z, sphincsplus_polyveck *h, sphincsplus_poly *c,
               const unsigned char *sig,
               uint64_t sphincsplus_k, uint64_t sphincsplus_l,
               uint64_t sphincsplus_polz_size_packed, uint64_t sphincsplus_omega);

#endif
