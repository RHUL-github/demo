#ifndef DILITHIUM_PARAMS_H
#define DILITHIUM_PARAMS_H

#define DILITHIUM_SEEDBYTES 32
#define DILITHIUM_CRHBYTES 48
#define DILITHIUM_N 256
#define DILITHIUM_Q 8380417
#define DILITHIUM_QBITS 23
#define DILITHIUM_ROOT_OF_UNITY 1753
#define DILITHIUM_D 14
#define DILITHIUM_GAMMA1 ((DILITHIUM_Q - 1)/16)
#define DILITHIUM_GAMMA2 (DILITHIUM_GAMMA1/2)
#define DILITHIUM_ALPHA (2*DILITHIUM_GAMMA2)

#endif
