#include <stdint.h>
#include "sphincsplus-params.h"
#include "sphincsplus-reduce.h"

/*************************************************
* Name:        montgomery_reduce
*
* Description: For finite field element a with 0 <= a <= Q*2^32,
*              compute r \equiv a*2^{-32} (mod Q) such that 0 <= r < 2*Q.
*
* Arguments:   - uint64_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t sphincsplus_montgomery_reduce(uint64_t a) {
  uint64_t t;

  t = a * SPHINCS_PLUS_QINV;
  t &= (1ULL << 32) - 1;
  t *= SPHINCS_PLUS_Q;
  t = a + t;
  t >>= 32;
  return t;
}

/*************************************************
* Name:        reduce32
*
* Description: For finite field element a, compute r \equiv a (mod Q)
*              such that 0 <= r < 2*Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t sphincsplus_reduce32(uint32_t a) {
  uint32_t t;

  t = a & 0x7FFFFF;
  a >>= 23;
  t += (a << 13) - a;
  return t;
}

/*************************************************
* Name:        csubq
*
* Description: Subtract Q if input coefficient is bigger than Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t sphincsplus_csubq(uint32_t a) {
  a -= SPHINCS_PLUS_Q;
  a += ((int32_t)a >> 31) & SPHINCS_PLUS_Q;
  return a;
}

/*************************************************
* Name:        freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t sphincsplus_freeze(uint32_t a) {
  a = sphincsplus_reduce32(a);
  a = sphincsplus_csubq(a);
  return a;
}
