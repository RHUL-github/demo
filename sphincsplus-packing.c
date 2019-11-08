#include "sphincsplus-params.h"
#include "sphincsplus-poly.h"
#include "sphincsplus-polyvec.h"
#include "sphincsplus-packing.h"

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - unsigned char pk[]: output byte array
*              - const unsigned char rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/
void sphincsplus_pack_pk(unsigned char *pk,
             const unsigned char rho[SPHINCS_PLUS_SEEDBYTES], const sphincsplus_polyveck *t1,
             uint64_t sphincsplus_k, uint64_t sphincsplus_polt1_size_packed)
{
  unsigned int i;

  for(i = 0; i < SPHINCS_PLUS_SEEDBYTES; ++i)
    pk[i] = rho[i];
  pk += SPHINCS_PLUS_SEEDBYTES;

  for(i = 0; i < sphincsplus_k; ++i)
    sphincsplus_polyt1_pack(pk + i*sphincsplus_polt1_size_packed, &t1->vec[i]);
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const unsigned char rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - unsigned char pk[]: byte array containing bit-packed pk
**************************************************/
void sphincsplus_unpack_pk(unsigned char rho[SPHINCS_PLUS_SEEDBYTES], sphincsplus_polyveck *t1,
               const unsigned char *pk,
               uint64_t sphincsplus_k, uint64_t sphincsplus_polt1_size_packed)
{
  unsigned int i;

  for(i = 0; i < SPHINCS_PLUS_SEEDBYTES; ++i)
    rho[i] = pk[i];
  pk += SPHINCS_PLUS_SEEDBYTES;

  for(i = 0; i < sphincsplus_k; ++i)
    sphincsplus_polyt1_unpack(&t1->vec[i], pk + i*sphincsplus_polt1_size_packed);
}

/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, key, tr, s1, s2, t0).
*
* Arguments:   - unsigned char sk[]: output byte array
*              - const unsigned char rho[]: byte array containing rho
*              - const unsigned char key[]: byte array containing key
*              - const unsigned char tr[]: byte array containing tr
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
*              - const polyveck *t0: pointer to vector t0
**************************************************/
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
             uint64_t sphincsplus_eta)
{
  unsigned int i;

  for(i = 0; i < SPHINCS_PLUS_SEEDBYTES; ++i)
    sk[i] = rho[i];
  sk += SPHINCS_PLUS_SEEDBYTES;

  for(i = 0; i < SPHINCS_PLUS_SEEDBYTES; ++i)
    sk[i] = key[i];
  sk += SPHINCS_PLUS_SEEDBYTES;

  for(i = 0; i < SPHINCS_PLUS_CRHBYTES; ++i)
    sk[i] = tr[i];
  sk += SPHINCS_PLUS_CRHBYTES;

  for(i = 0; i < sphincsplus_l; ++i)
    sphincsplus_polyeta_pack(sk + i*sphincsplus_poleta_size_packed, &s1->vec[i], sphincsplus_eta);
  sk += sphincsplus_l*sphincsplus_poleta_size_packed;

  for(i = 0; i < sphincsplus_k; ++i)
    sphincsplus_polyeta_pack(sk + i*sphincsplus_poleta_size_packed, &s2->vec[i], sphincsplus_eta);
  sk += sphincsplus_k*sphincsplus_poleta_size_packed;

  for(i = 0; i < sphincsplus_k; ++i)
    sphincsplus_polyt0_pack(sk + i*sphincsplus_polt0_size_packed, &t0->vec[i]);
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, key, tr, s1, s2, t0).
*
* Arguments:   - const unsigned char rho[]: output byte array for rho
*              - const unsigned char key[]: output byte array for key
*              - const unsigned char tr[]: output byte array for tr
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - const polyveck *r0: pointer to output vector t0
*              - unsigned char sk[]: byte array containing bit-packed sk
**************************************************/
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
               uint64_t sphincsplus_eta)
{
  unsigned int i;

  for(i = 0; i < SPHINCS_PLUS_SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += SPHINCS_PLUS_SEEDBYTES;

  for(i = 0; i < SPHINCS_PLUS_SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += SPHINCS_PLUS_SEEDBYTES;

  for(i = 0; i < SPHINCS_PLUS_CRHBYTES; ++i)
    tr[i] = sk[i];
  sk += SPHINCS_PLUS_CRHBYTES;

  for(i=0; i < sphincsplus_l; ++i)
    sphincsplus_polyeta_unpack(&s1->vec[i], sk + i*sphincsplus_poleta_size_packed, sphincsplus_eta);
  sk += sphincsplus_l*sphincsplus_poleta_size_packed;

  for(i=0; i < sphincsplus_k; ++i)
    sphincsplus_polyeta_unpack(&s2->vec[i], sk + i*sphincsplus_poleta_size_packed, sphincsplus_eta);
  sk += sphincsplus_k*sphincsplus_poleta_size_packed;

  for(i=0; i < sphincsplus_k; ++i)
    sphincsplus_polyt0_unpack(&t0->vec[i], sk + i*sphincsplus_polt0_size_packed);
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (z, h, c).
*
* Arguments:   - unsigned char sig[]: output byte array
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
*              - const poly *c: pointer to challenge polynomial
**************************************************/
void sphincsplus_pack_sig(unsigned char *sig,
              const sphincsplus_polyvecl *z, const sphincsplus_polyveck *h, const sphincsplus_poly *c,
              uint64_t sphincsplus_k, uint64_t sphincsplus_l,
              uint64_t sphincsplus_polz_size_packed, uint64_t sphincsplus_omega)
{
  unsigned int i, j, k;
  uint64_t signs, mask;

  for(i = 0; i < sphincsplus_l; ++i)
    sphincsplus_polyz_pack(sig + i*sphincsplus_polz_size_packed, &z->vec[i]);
  sig += sphincsplus_l*sphincsplus_polz_size_packed;

  /* Encode h */
  k = 0;
  for(i = 0; i < sphincsplus_k; ++i) {
    for(j = 0; j < SPHINCS_PLUS_N; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = j;

    sig[sphincsplus_omega + i] = k;
  }
  while(k < sphincsplus_omega) sig[k++] = 0;
  sig += sphincsplus_omega + sphincsplus_k;

  /* Encode c */
  signs = 0;
  mask = 1;
  for(i = 0; i < SPHINCS_PLUS_N/8; ++i) {
    sig[i] = 0;
    for(j = 0; j < 8; ++j) {
      if(c->coeffs[8*i+j] != 0) {
        sig[i] |= (1U << j);
        if(c->coeffs[8*i+j] == (SPHINCS_PLUS_Q - 1)) signs |= mask;
        mask <<= 1;
      }
    }
  }
  sig += SPHINCS_PLUS_N/8;
  for(i = 0; i < 8; ++i)
    sig[i] = signs >> 8*i;
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (z, h, c).
*
* Arguments:   - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - poly *c: pointer to output challenge polynomial
*              - const unsigned char sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int sphincsplus_unpack_sig(sphincsplus_polyvecl *z, sphincsplus_polyveck *h, sphincsplus_poly *c,
               const unsigned char *sig,
               uint64_t sphincsplus_k, uint64_t sphincsplus_l,
               uint64_t sphincsplus_polz_size_packed, uint64_t sphincsplus_omega)
{
    unsigned int i, j, k;
    uint64_t signs;

    for(i = 0; i < sphincsplus_l; ++i)
        sphincsplus_polyz_unpack(&z->vec[i], sig + i*sphincsplus_polz_size_packed);
    sig += sphincsplus_l*sphincsplus_polz_size_packed;

    /* Decode h */
    k = 0;
    for(i = 0; i < sphincsplus_k; ++i) {
        for(j = 0; j < SPHINCS_PLUS_N; ++j)
            h->vec[i].coeffs[j] = 0;

        if(sig[sphincsplus_omega + i] < k || sig[sphincsplus_omega + i] > sphincsplus_omega)
            return 1;

        for(j = k; j < sig[sphincsplus_omega + i]; ++j) {
            /* Coefficients are ordered for strong unforgeability */
            if(j > k && sig[j] <= sig[j-1]) return 1;
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[sphincsplus_omega + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for(j = k; j < sphincsplus_omega; ++j)
        if(sig[j])
            return 1;

    sig += sphincsplus_omega + sphincsplus_k;

    /* Decode c */
    for(i = 0; i < SPHINCS_PLUS_N; ++i)
        c->coeffs[i] = 0;

    signs = 0;
    for(i = 0; i < 8; ++i)
        signs |= (uint64_t)sig[SPHINCS_PLUS_N/8+i] << 8*i;

    /* Extra sign bits are zero for strong unforgeability */
    if(signs >> 60)
        return 1;

    for(i = 0; i < SPHINCS_PLUS_N/8; ++i) {
        for(j = 0; j < 8; ++j) {
            if((sig[i] >> j) & 0x01) {
                c->coeffs[8*i+j] = 1;
                c->coeffs[8*i+j] ^= -(signs & 1) & (1 ^ (SPHINCS_PLUS_Q-1));
                signs >>= 1;
            }
        }
    }

    return 0;
}
