#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "sphincsplus-params.h"

void sphincsplus_ntt(uint32_t p[SPHINCS_PLUS_N]);
void sphincsplus_invntt_frominvmont(uint32_t p[SPHINCS_PLUS_N]);

#endif
